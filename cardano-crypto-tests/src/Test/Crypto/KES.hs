{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE DerivingVia          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE QuantifiedConstraints #-}
{-# LANGUAGE MultiParamTypeClasses #-}

{-# OPTIONS_GHC -Wno-orphans #-}

{- HLINT ignore "Use head" -}

module Test.Crypto.KES
  ( tests
  )
where

import Data.Proxy (Proxy(..))
import Data.List (foldl')
import qualified Data.ByteString as BS
import Data.Set (Set)
import qualified Data.Set as Set
import Foreign.Ptr (WordPtr)
import Data.IORef
import Data.Foldable (traverse_)
import GHC.TypeNats (KnownNat)

import Control.Tracer
import Control.Monad.Class.MonadST
import Control.Monad.Class.MonadThrow
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad (void)

import Cardano.Crypto.DSIGN hiding (Signable)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES
import Cardano.Crypto.KES.ForgetMock
import Cardano.Crypto.Util (SignableRepresentation(..))
import Cardano.Crypto.MLockedSeed
import qualified Cardano.Crypto.Libsodium as NaCl
import Cardano.Crypto.MonadMLock

import Test.QuickCheck
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckMaxSize(..))
import Test.Tasty.HUnit (testCase, Assertion, assertEqual, assertBool)

import Test.Crypto.Util (
  ToCBOR,
  FromCBOR,
  Message,
  prop_raw_serialise,
  prop_size_serialise,
  prop_cbor_with,
  prop_cbor,
  prop_cbor_size,
  prop_cbor_direct_vs_class,
  prop_no_thunks_IO,
  hexBS,
  doesNotThrow,
  noExceptionsThrown,
  Lock,
  withLock,
  )
import Test.Crypto.RunIO (RunIO (..))
import Test.Crypto.Instances (withMLockedSeedFromPSB)
import Test.Crypto.AllocLog

{- HLINT ignore "Reduce duplication" -}
{- HLINT ignore "Use head" -}

--
-- The list of all tests
--
tests :: Lock -> TestTree
tests lock =
  testGroup "Crypto.KES"
  [ testKESAlloc (Proxy :: Proxy (SingleKES Ed25519DSIGNM)) "SingleKES"
  , testKESAlloc (Proxy :: Proxy (Sum1KES Ed25519DSIGNM Blake2b_256)) "Sum1KES"
  , testKESAlloc (Proxy :: Proxy (Sum2KES Ed25519DSIGNM Blake2b_256)) "Sum2KES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (MockKES 7))               "MockKES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (SimpleKES Ed25519DSIGNM 7)) "SimpleKES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (SingleKES Ed25519DSIGNM))   "SingleKES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (Sum1KES Ed25519DSIGNM Blake2b_256)) "Sum1KES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (Sum2KES Ed25519DSIGNM Blake2b_256)) "Sum2KES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (Sum5KES Ed25519DSIGNM Blake2b_256)) "Sum5KES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (CompactSum1KES Ed25519DSIGNM Blake2b_256)) "CompactSum1KES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (CompactSum2KES Ed25519DSIGNM Blake2b_256)) "CompactSum2KES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (CompactSum5KES Ed25519DSIGNM Blake2b_256)) "CompactSum5KES"
  ]

-- We normally ensure that we avoid naively comparing signing keys by not
-- providing instances, but for tests it is fine, so we provide the orphan
-- instances here.

instance Show (SignKeyKES (SingleKES Ed25519DSIGNM)) where
  show (SignKeySingleKES (SignKeyEd25519DSIGNM mlsb)) =
    let bytes = NaCl.mlsbAsByteString mlsb
        hexstr = hexBS bytes
    in "SignKeySingleKES (SignKeyEd25519DSIGNM " ++ hexstr ++ ")"

instance Show (SignKeyKES (SumKES h d)) where
  show _ = "<SignKeySumKES>"

instance Show (SignKeyKES (CompactSingleKES Ed25519DSIGNM)) where
  show (SignKeyCompactSingleKES (SignKeyEd25519DSIGNM mlsb)) =
    let bytes = NaCl.mlsbAsByteString mlsb
        hexstr = hexBS bytes
    in "SignKeyCompactSingleKES (SignKeyEd25519DSIGNM " ++ hexstr ++ ")"

instance Show (SignKeyKES (CompactSumKES h d)) where
  show _ = "<SignKeyCompactSumKES>"

deriving via (PureMEq (SignKeyKES (MockKES t))) instance Applicative m => MEq m (SignKeyKES (MockKES t))

deriving newtype instance (MEq m (SignKeyDSIGNM d)) => MEq m (SignKeyKES (SingleKES d))

instance ( MonadST m
         , MEq m (SignKeyKES d)
         , Eq (VerKeyKES d)
         , KnownNat (SeedSizeKES d)
         ) => MEq m (SignKeyKES (SumKES h d)) where
  equalsM (SignKeySumKES s r v1 v2) (SignKeySumKES s' r' v1' v2') =
    (s, r, PureMEq v1, PureMEq v2) ==! (s', r', PureMEq v1', PureMEq v2')

deriving newtype instance (MEq m (SignKeyDSIGNM d)) => MEq m (SignKeyKES (CompactSingleKES d))

instance ( MonadST m
         , MEq m (SignKeyKES d)
         , Eq (VerKeyKES d)
         , KnownNat (SeedSizeKES d)
         ) => MEq m (SignKeyKES (CompactSumKES h d)) where
  equalsM (SignKeyCompactSumKES s r v1 v2) (SignKeyCompactSumKES s' r' v1' v2') =
    (s, r, PureMEq v1, PureMEq v2) ==! (s', r', PureMEq v1', PureMEq v2')

testKESAlloc
  :: forall v.
     ( (forall m. (MonadThrow m, MonadST m) => KESSignAlgorithm m v)
     , ContextKES v ~ ()
     )
  => Proxy v
  -> String
  -> TestTree
testKESAlloc _p n =
  testGroup n
    [ testGroup "Forget mock"
      [ testCase "genKey" $ testForgetGenKeyKES _p
      , testCase "updateKey" $ testForgetUpdateKeyKES _p
      ]
    , testGroup "Low-level mlocked allocations"
      [ testCase "genKey" $ testMLockGenKeyKES _p
      -- , testCase "updateKey" $ testMLockUpdateKeyKES _p
      ]
    ]

testForgetGenKeyKES
  :: forall v.
     ( KESSignAlgorithm (LogT (GenericEvent ForgetMockEvent) IO) v
     )
  => Proxy v
  -> Assertion
testForgetGenKeyKES _p = do
  logVar <- newIORef []
  let tracer :: Tracer (LogT (GenericEvent ForgetMockEvent) IO) (GenericEvent ForgetMockEvent)
      tracer = Tracer (\ev -> liftIO $ modifyIORef logVar (++ [ev]))
  runLogT tracer $ do
    seed <- MLockedSeed <$> mlsbFromByteString (BS.replicate 1024 23)
    sk <- genKeyKES @(LogT (GenericEvent ForgetMockEvent) IO) @(ForgetMockKES v) seed
    mlockedSeedFinalize seed
    forgetSignKeyKES sk
  result <- map concreteEvent <$> readIORef logVar
  assertBool ("Unexpected log: " ++ show result) $ case result of
    [GEN a, DEL b] ->
      -- End of last period, so no update happened
      a == b
    _ -> False
  return ()

testForgetUpdateKeyKES
  :: forall v.
     ( KESSignAlgorithm (LogT (GenericEvent ForgetMockEvent) IO) v
     , ContextKES v ~ ()
     )
  => Proxy v
  -> Assertion
testForgetUpdateKeyKES _p = do
  logVar <- newIORef []
  let tracer :: Tracer (LogT (GenericEvent ForgetMockEvent) IO) (GenericEvent ForgetMockEvent)
      tracer = Tracer (\ev -> liftIO $ modifyIORef logVar (++ [ev]))
  runLogT tracer $ do
    seed <- MLockedSeed <$> NaCl.mlsbFromByteString (BS.replicate 1024 23)
    sk <- genKeyKES @(LogT (GenericEvent ForgetMockEvent) IO) @(ForgetMockKES v) seed
    mlockedSeedFinalize seed
    msk' <- updateKES () sk 0
    forgetSignKeyKES sk
    traverse_ forgetSignKeyKES msk'
  result <- map concreteEvent <$> readIORef logVar

  assertBool ("Unexpected log: " ++ show result) $ case result of
    [GEN a, UPD b c, DEL d, DEL e] ->
      -- Regular update
      a == b && d == a && e == c
    [GEN a, NOUPD, DEL b] ->
      -- End of last period, so no update happened
      a == b
    _ -> False


matchAllocLog :: [AllocEvent] -> Set WordPtr
matchAllocLog = foldl' (flip go) Set.empty
  where
    go (AllocEv ptr) = Set.insert ptr
    go (FreeEv ptr) = Set.delete ptr
    go (MarkerEv _) = id

testMLockGenKeyKES
  :: forall v.
     ( KESSignAlgorithm (AllocLogT IO) v
     )
  => Proxy v
  -> Assertion
testMLockGenKeyKES _p = do
  accumVar <- newIORef []
  let tracer = Tracer (\ev -> liftIO $ modifyIORef accumVar (++ [ev]))
  runAllocLogT tracer $ do
    pushAllocLogEvent $ MarkerEv "gen seed"
    (seed :: MLockedSeed (SeedSizeKES v)) <- MLockedSeed <$> NaCl.mlsbFromByteString (BS.replicate 1024 23)
    pushAllocLogEvent $ MarkerEv "gen key"
    sk <- genKeyKES @_ @v seed
    pushAllocLogEvent $ MarkerEv "forget key"
    forgetSignKeyKES sk
    pushAllocLogEvent $ MarkerEv "forget seed"
    mlockedSeedFinalize seed
    pushAllocLogEvent $ MarkerEv "done"
  after <- readIORef accumVar
  let evset = matchAllocLog after
  assertEqual "all allocations deallocated" Set.empty evset

{-# NOINLINE testKESAlgorithm#-}
testKESAlgorithm
  :: forall m v.
     ( ToCBOR (VerKeyKES v)
     , FromCBOR (VerKeyKES v)
     , MEq IO (SignKeyKES v)   -- only monadic MEq for signing keys
     , Show (SignKeyKES v) -- fake instance defined locally
     , ToCBOR (SigKES v)
     , FromCBOR (SigKES v)
     , Signable v ~ SignableRepresentation
     , ContextKES v ~ ()
     , KESSignAlgorithm m v
     -- , KESSignAlgorithm IO v -- redundant for now
     , UnsoundKESSignAlgorithm IO v
     )
  => Lock
  -> Proxy m
  -> Proxy v
  -> String
  -> TestTree
testKESAlgorithm lock _pm _pv n =
  testGroup n
    [ testProperty "only gen signkey" $ prop_onlyGenSignKeyKES @v lock Proxy
    , testProperty "only gen verkey" $ prop_onlyGenVerKeyKES @v lock Proxy
    , testProperty "one update signkey" $ prop_oneUpdateSignKeyKES lock (Proxy @IO) (Proxy @v)
    , testProperty "all updates signkey" $ prop_allUpdatesSignKeyKES lock (Proxy @IO) (Proxy @v)
    , testProperty "total periods" $ prop_totalPeriodsKES lock (Proxy @IO) (Proxy @v)
    , testGroup "NoThunks"
      [ testProperty "VerKey" $
          ioPropertyWithSK @v lock $ \sk ->
            prop_no_thunks_IO (deriveVerKeyKES sk)
      , testProperty "SignKey" $
          ioPropertyWithSK @v lock $
            prop_no_thunks_IO . return
      , testProperty "SignKey evolved" $
          ioPropertyWithSK @v lock $ \sk ->
            bracket
              (updateKES () sk 0)
              (maybe (return ()) forgetSignKeyKES)
              (prop_no_thunks_IO . return)
      , testProperty "Sig"     $ \seedPSB (msg :: Message) ->
          ioProperty $ withLock lock $ fmap conjoin $ withAllUpdatesKES @IO @v seedPSB $ \t sk -> do
            prop_no_thunks_IO (signKES () t msg sk)
      ]

    , testProperty "same VerKey "  $ prop_deriveVerKeyKES (Proxy @IO) (Proxy @v)
    , testGroup "serialisation"

      [ testGroup "raw ser only"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              return $ (rawDeserialiseVerKeyKES . rawSerialiseVerKeyKES $ vk) === Just vk
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyKES sk
              equals <- bracket
                          (rawDeserialiseSignKeyKES serialized)
                          (maybe (return ()) forgetSignKeyKES)
                          (\msk' -> Just sk ==! msk')
              return $
                counterexample (show serialized) equals
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigKES v <- signKES () 0 msg sk
              return $ (rawDeserialiseSigKES . rawSerialiseSigKES $ sig) === Just sig
        ]
      , testGroup "size"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              return $ (fromIntegral . BS.length . rawSerialiseVerKeyKES $ vk) === sizeVerKeyKES (Proxy @v)
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- rawSerialiseSignKeyKES sk
              evaluate ((fromIntegral . BS.length $ serialized) == sizeSignKeyKES (Proxy @v))
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigKES v <- signKES () 0 msg sk
              return $ (fromIntegral . BS.length . rawSerialiseSigKES $ sig) === sizeSigKES (Proxy @v)
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              return $ prop_cbor_with encodeVerKeyKES decodeVerKeyKES vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigKES v <- signKES () 0 msg sk
              return $ prop_cbor_with encodeSigKES decodeSigKES sig
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyKES', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigKES v <- signKES () 0 msg sk
              return $ prop_cbor sig
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyKES', see above.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigKES v <- signKES () 0 msg sk
              return $ prop_cbor_size sig
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              return $ prop_cbor_direct_vs_class encodeVerKeyKES vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ \(msg :: Message) ->
            ioPropertyWithSK @v lock $ \sk -> do
              sig :: SigKES v <- signKES () 0 msg sk
              return $ prop_cbor_direct_vs_class encodeSigKES sig
        ]
      ]

    , testGroup "verify"
      [ testProperty "positive"           $ prop_verifyKES_positive         @IO @v Proxy Proxy
      , testProperty "negative (key)"     $ prop_verifyKES_negative_key     @IO @v Proxy Proxy
      , testProperty "negative (message)" $ prop_verifyKES_negative_message @IO @v Proxy Proxy
      , adjustOption (\(QuickCheckMaxSize sz) -> QuickCheckMaxSize (min sz 50)) $
        testProperty "negative (period)"  $ prop_verifyKES_negative_period  @IO @v Proxy Proxy
      ]

    , testGroup "serialisation of all KES evolutions"
      [ testProperty "VerKey"  $ prop_serialise_VerKeyKES  @IO @v Proxy Proxy
      , testProperty "Sig"     $ prop_serialise_SigKES     @IO @v Proxy Proxy
      ]

    -- TODO: this doesn't pass right now, see
    -- 'prop_key_overwritten_after_forget' for details.
    --
    -- , testGroup "forgetting"
    --   [ testProperty "key overwritten after forget" $ prop_key_overwritten_after_forget (Proxy @v)
    --   ]

    ]

-- | Wrap an IO action that requires a 'SignKeyKES' into one that takes an
-- mlocked seed to generate the key from. The key is bracketed off to ensure
-- timely forgetting. Special care must be taken to not leak the key outside of
-- the wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
withSK :: ( MonadST m
          , MonadThrow m
          , KESSignAlgorithm m v
          ) => PinnedSizedBytes (SeedSizeKES v) -> (SignKeyKES v -> m b) -> m b
withSK seedPSB =
  bracket
    (withMLockedSeedFromPSB seedPSB genKeyKES)
    forgetSignKeyKES

-- | Wrap an IO action that requires a 'SignKeyKES' into a 'Property' that
-- takes a non-mlocked seed (provided as a 'PinnedSizedBytes' of the
-- appropriate size). The key, and the mlocked seed necessary to generate it,
-- are bracketed off, to ensure timely forgetting and avoid leaking mlocked
-- memory. Special care must be taken to not leak the key outside of the
-- wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
ioPropertyWithSK :: forall v a. (Testable a, KESSignAlgorithm IO v)
                 => Lock
                 -> (SignKeyKES v -> IO a)
                 -> PinnedSizedBytes (SeedSizeKES v)
                 -> Property
ioPropertyWithSK lock action seedPSB =
  ioProperty $ withLock lock $ withSK seedPSB action

-- TODO: This doesn't actually pass right now, for various reasons:
-- - MockKES and SimpleKES don't actually implement secure forgetting;
--   forgetSignKeyKES is a no-op for these algorithms, and obviously that means
--   forgetting won't actually erase the key
-- prop_key_overwritten_after_forget
--   :: forall v.
--      (KESSignAlgorithm IO v
--      )
--   => Proxy v
--   -> PinnedSizedBytes (SeedSizeKES v)
--   -> Property
-- prop_key_overwritten_after_forget _ seedPSB =
--   ioProperty . withMLSBFromPSB seedPSB $ \seed -> do
--     sk <- genKeyKES @IO @v seed
--
--     before <- rawSerialiseSignKeyKES sk
--     forgetSignKeyKES sk
--     after <- rawSerialiseSignKeyKES sk
--
--     NaCl.mlsbFinalize seed
--
--     return (before =/= after)

prop_onlyGenSignKeyKES
  :: forall v.
      KESSignAlgorithm IO v
  => Lock -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_onlyGenSignKeyKES lock _ =
  ioPropertyWithSK @v lock $ const noExceptionsThrown

prop_onlyGenVerKeyKES
  :: forall v.
      KESSignAlgorithm IO v
  => Lock -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_onlyGenVerKeyKES lock _ =
  ioPropertyWithSK @v lock $ doesNotThrow . deriveVerKeyKES

prop_oneUpdateSignKeyKES
  :: forall m v.
        ( ContextKES v ~ ()
        , RunIO m
        , MonadFail m
        , MonadST m
        , MonadThrow m
        , KESSignAlgorithm m v
        )
  => Lock -> Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_oneUpdateSignKeyKES lock _ _ seedPSB =
  ioProperty . withLock lock . io . withMLockedSeedFromPSB seedPSB $ \seed -> do
    sk <- genKeyKES @m @v seed
    msk' <- updateKES @m () sk 0
    forgetSignKeyKES sk
    maybe (return ()) forgetSignKeyKES msk'
    return True

prop_allUpdatesSignKeyKES
  :: forall m v.
        ( ContextKES v ~ ()
        , RunIO m
        , MonadIO m
        , MonadST m
        , MonadThrow m
        , KESSignAlgorithm m v
        )
  => Lock -> Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_allUpdatesSignKeyKES lock _ _ seedPSB =
  ioProperty . withLock lock . io $ do
    void $ withAllUpdatesKES_ @m @v seedPSB $ const (return ())

-- | If we start with a signing key, we can evolve it a number of times so that
-- the total number of signing keys (including the initial one) equals the
-- total number of periods for this algorithm.
--
prop_totalPeriodsKES
  :: forall m v.
        ( ContextKES v ~ ()
        , RunIO m
        , MonadIO m
        , MonadST m
        , MonadThrow m
        , KESSignAlgorithm m v
        )
  => Lock -> Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_totalPeriodsKES lock _ _ seed =
    ioProperty . withLock lock $ do
        sks <- io $ withAllUpdatesKES_ @m @v seed (const . return $ ())
        return $
          totalPeriods > 0 ==>
          counterexample (show totalPeriods) $
          counterexample (show $ length sks) $
          length sks === totalPeriods
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))


-- | If we start with a signing key, and all its evolutions, the verification
-- keys we derive from each one are the same.
--
prop_deriveVerKeyKES
  :: forall m v.
      ( ContextKES v ~ ()
      , RunIO m
      , MonadIO m
      , MonadST m
      , MonadThrow m
      , KESSignAlgorithm m v
      )
  => Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_deriveVerKeyKES _ _ seedPSB =
    ioProperty $ do
        vk_0 <- io $ do
          sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @m @v
          vk_0 <- deriveVerKeyKES @m sk_0
          forgetSignKeyKES sk_0
          return vk_0

        vks <- io $ withAllUpdatesKES_ seedPSB $ deriveVerKeyKES @m
        return $
          counterexample (show vks) $
          conjoin (map (vk_0 ===) vks)


-- | If we take an initial signing key, a sequence of messages to sign, and
-- sign each one with an updated key, we can verify each one for the
-- corresponding period.
--
prop_verifyKES_positive
  :: forall m v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO m
     , MonadIO m
     , MonadST m
     , MonadThrow m
     , KESSignAlgorithm m v
     )
  => Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Gen Property
prop_verifyKES_positive _ _ seedPSB = do
    xs :: [Message] <- vectorOf totalPeriods arbitrary
    return $ checkCoverage $
      cover 1 (length xs >= totalPeriods) "Message count covers total periods" $
      not (null xs) ==>
      ioProperty $ fmap conjoin $ io $ do
        sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @m @v
        vk <- deriveVerKeyKES @m sk_0
        forgetSignKeyKES sk_0
        withAllUpdatesKES seedPSB $ \t sk -> do
          let x = cycle xs !! fromIntegral t
          sig <- signKES () t x sk
          let verResult = verifyKES () vk t x sig
          return $
            counterexample ("period " ++ show t ++ "/" ++ show totalPeriods) $
            verResult === Right ()
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))


-- | If we sign a message @a@with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using a verification key
-- corresponding to a different signing key, then the verification fails.
--
prop_verifyKES_negative_key
  :: forall m v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO m
     , MonadIO m
     , MonadST m
     , MonadThrow m
     , KESSignAlgorithm m v
     )
  => Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_verifyKES_negative_key _ _ seedPSB seedPSB' x =
    seedPSB /= seedPSB' ==> ioProperty $ fmap conjoin $ io $ do
        sk_0' <- withMLockedSeedFromPSB seedPSB' $ genKeyKES @m @v
        vk' <- deriveVerKeyKES sk_0'
        forgetSignKeyKES sk_0'
        withAllUpdatesKES seedPSB $ \t sk -> do
          sig <- signKES () t x sk
          let verResult = verifyKES () vk' t x sig
          return $
            counterexample ("period " ++ show t) $
            verResult =/= Right ()

-- | If we sign a message @a@with one list of signing key evolutions, if we
-- try to verify the signature with a message other than @a@, then the
-- verification fails.
--
prop_verifyKES_negative_message
  :: forall m v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO m
     , MonadIO m
     , MonadST m
     , MonadThrow m
     , KESSignAlgorithm m v
     )
  => Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message -> Message
  -> Property
prop_verifyKES_negative_message _ _ seedPSB x x' =
    x /= x' ==> ioProperty $ fmap conjoin $ io $ do
        sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @m @v
        vk <- deriveVerKeyKES @m sk_0
        forgetSignKeyKES sk_0
        withAllUpdatesKES seedPSB $ \t sk -> do
          sig <- signKES () t x sk
          let verResult = verifyKES () vk t x' sig
          return $
            counterexample ("period " ++ show t) $
            verResult =/= Right ()

-- | If we sign a message @a@with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using the right verification
-- key but at a different period than the key used for signing, then the
-- verification fails.
--
prop_verifyKES_negative_period
  :: forall m v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO m
     , MonadIO m
     , MonadST m
     , MonadThrow m
     , KESSignAlgorithm m v
     )
  => Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_verifyKES_negative_period _ _ seedPSB x =
    ioProperty $ fmap conjoin $ io $ do
        sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @m @v
        vk <- deriveVerKeyKES @m sk_0
        forgetSignKeyKES sk_0
        withAllUpdatesKES seedPSB $ \t sk -> do
            sig <- signKES () t x sk
            return $
              conjoin [ counterexample ("periods " ++ show (t, t')) $
                        verifyKES () vk t' x sig =/= Right ()
                      | t' <- [0..totalPeriods-1]
                      , t /= t'
                      ]
  where
    totalPeriods :: Word
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))


-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'VerKeyKES' on /all/ the KES key evolutions.
--
prop_serialise_VerKeyKES
  :: forall m v.
     ( ContextKES v ~ ()
     , RunIO m
     , MonadIO m
     , MonadST m
     , MonadThrow m
     , KESSignAlgorithm m v
     )
  => Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Property
prop_serialise_VerKeyKES _ _ seedPSB =
    ioProperty $ fmap conjoin $ io $ do
        withAllUpdatesKES @m @v seedPSB $ \t sk -> do
          vk <- deriveVerKeyKES @m sk
          return $
                 counterexample ("period " ++ show t) $
                 counterexample ("vkey " ++ show vk) $
                    prop_raw_serialise rawSerialiseVerKeyKES
                                       rawDeserialiseVerKeyKES vk
                .&. prop_cbor_with encodeVerKeyKES
                                   decodeVerKeyKES vk
                .&. prop_size_serialise rawSerialiseVerKeyKES
                                        (sizeVerKeyKES (Proxy @v)) vk

-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'SigKES' on /all/ the KES key evolutions.
--
prop_serialise_SigKES
  :: forall m v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , Show (SignKeyKES v)
     , RunIO m
     , MonadIO m
     , MonadST m
     , MonadThrow m
     , KESSignAlgorithm m v
     )
  => Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_serialise_SigKES _ _ seedPSB x =
    ioProperty $ fmap conjoin $ io $ do
        withAllUpdatesKES @m @v seedPSB $ \t sk -> do
            sig <- signKES () t x sk
            return $
              counterexample ("period " ++ show t) $
              counterexample ("vkey "   ++ show sk) $
              counterexample ("sig "    ++ show sig) $
                  prop_raw_serialise rawSerialiseSigKES
                                     rawDeserialiseSigKES sig
              .&. prop_cbor_with encodeSigKES
                                 decodeSigKES sig
              .&. prop_size_serialise rawSerialiseSigKES
                                      (sizeSigKES (Proxy @v)) sig

--
-- KES test utils
--

withAllUpdatesKES_ :: forall m v a.
                  ( KESSignAlgorithm m v
                  , ContextKES v ~ ()
                  , MonadST m
                  , MonadThrow m
                  )
              => PinnedSizedBytes (SeedSizeKES v)
              -> (SignKeyKES v -> m a)
              -> m [a]
withAllUpdatesKES_ seedPSB f = do
  withAllUpdatesKES seedPSB (const f)

withAllUpdatesKES :: forall m v a.
                  ( KESSignAlgorithm m v
                  , ContextKES v ~ ()
                  , MonadST m
                  , MonadThrow m
                  )
              => PinnedSizedBytes (SeedSizeKES v)
              -> (Word -> SignKeyKES v -> m a)
              -> m [a]
withAllUpdatesKES seedPSB f = withMLockedSeedFromPSB seedPSB $ \seed -> do
  sk_0 <- genKeyKES seed
  go sk_0 0
  where
    go :: SignKeyKES v -> Word -> m [a]
    go sk t = do
      x <- f t sk
      msk' <- updateKES () sk t
      case msk' of
        Nothing -> do
          forgetSignKeyKES sk
          return [x]
        Just sk' -> do
          forgetSignKeyKES sk
          xs <- go sk' (t + 1)
          return $ x:xs

