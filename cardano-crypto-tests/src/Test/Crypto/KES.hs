{-# LANGUAGE AllowAmbiguousTypes  #-}
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
import Foreign.Ptr (WordPtr, plusPtr)
import Data.IORef
import GHC.TypeNats (KnownNat, natVal)

import Control.Concurrent.MVar (newMVar, takeMVar, putMVar)
import Control.Monad (void, when)
import Control.Monad.Class.MonadST
import Control.Monad.Class.MonadThrow
import Control.Monad.IO.Class (liftIO)
import Control.Tracer

import Cardano.Crypto.DSIGN hiding (Signable)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES
import Cardano.Crypto.DirectSerialise (DirectSerialise, directSerialise, DirectDeserialise)
import Cardano.Crypto.Util (SignableRepresentation(..))
import Cardano.Crypto.Libsodium
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Libsodium.Memory
  ( copyMem
  , allocaBytes
  , packByteStringCStringLen
  )
import Cardano.Crypto.PinnedSizedBytes

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
  directSerialiseToBS,
  directDeserialiseFromBS,
  )
import Test.Crypto.EqST
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
  [ testKESAlloc (Proxy @(SingleKES Ed25519DSIGN)) "SingleKES"
  , testKESAlloc (Proxy @(Sum1KES Ed25519DSIGN Blake2b_256)) "Sum1KES"
  , testKESAlloc (Proxy @(Sum2KES Ed25519DSIGN Blake2b_256)) "Sum2KES"
  , testKESAlgorithm @(MockKES 7)               lock "MockKES"
  , testKESAlgorithm @(SimpleKES Ed25519DSIGN 7) lock "SimpleKES"
  , testKESAlgorithm @(SingleKES Ed25519DSIGN)   lock "SingleKES"
  , testKESAlgorithm @(Sum1KES Ed25519DSIGN Blake2b_256) lock "Sum1KES"
  , testKESAlgorithm @(Sum2KES Ed25519DSIGN Blake2b_256) lock "Sum2KES"
  , testKESAlgorithm @(Sum5KES Ed25519DSIGN Blake2b_256) lock "Sum5KES"
  , testKESAlgorithm @(CompactSum1KES Ed25519DSIGN Blake2b_256) lock "CompactSum1KES"
  , testKESAlgorithm @(CompactSum2KES Ed25519DSIGN Blake2b_256) lock "CompactSum2KES"
  , testKESAlgorithm @(CompactSum5KES Ed25519DSIGN Blake2b_256) lock "CompactSum5KES"
  ]

-- We normally ensure that we avoid naively comparing signing keys by not
-- providing instances, but for tests it is fine, so we provide the orphan
-- instances here.

instance Show (SignKeyKES (SingleKES Ed25519DSIGN)) where
  show (SignKeySingleKES (SignKeyEd25519DSIGNM mlsb)) =
    let bytes = mlsbAsByteString mlsb
        hexstr = hexBS bytes
    in "SignKeySingleKES (SignKeyEd25519DSIGNM " ++ hexstr ++ ")"

instance Show (SignKeyKES (SumKES h d)) where
  show _ = "<SignKeySumKES>"

instance Show (SignKeyKES (CompactSingleKES Ed25519DSIGN)) where
  show (SignKeyCompactSingleKES (SignKeyEd25519DSIGNM mlsb)) =
    let bytes = mlsbAsByteString mlsb
        hexstr = hexBS bytes
    in "SignKeyCompactSingleKES (SignKeyEd25519DSIGNM " ++ hexstr ++ ")"

instance Show (SignKeyKES (CompactSumKES h d)) where
  show _ = "<SignKeyCompactSumKES>"

deriving via (PureEqST (SignKeyKES (MockKES t))) instance EqST (SignKeyKES (MockKES t))

deriving newtype instance (EqST (SignKeyDSIGNM d)) => EqST (SignKeyKES (SingleKES d))

instance ( EqST (SignKeyKES d)
         , Eq (VerKeyKES d)
         , KnownNat (SeedSizeKES d)
         ) => EqST (SignKeyKES (SumKES h d)) where
  equalsM (SignKeySumKES s r v1 v2) (SignKeySumKES s' r' v1' v2') =
    (s, r, PureEqST v1, PureEqST v2) ==! (s', r', PureEqST v1', PureEqST v2')

deriving newtype instance (EqST (SignKeyDSIGNM d)) => EqST (SignKeyKES (CompactSingleKES d))

instance ( EqST (SignKeyKES d)
         , Eq (VerKeyKES d)
         , KnownNat (SeedSizeKES d)
         ) => EqST (SignKeyKES (CompactSumKES h d)) where
  equalsM (SignKeyCompactSumKES s r v1 v2) (SignKeyCompactSumKES s' r' v1' v2') =
    (s, r, PureEqST v1, PureEqST v2) ==! (s', r', PureEqST v1', PureEqST v2')

testKESAlloc
  :: forall v.
     ( KESAlgorithm v
     )
  => Proxy v
  -> String
  -> TestTree
testKESAlloc _p n =
  testGroup n
    [ testGroup "Low-level mlocked allocations"
      [ testCase "genKey" $ testMLockGenKeyKES _p
      -- , testCase "updateKey" $ testMLockUpdateKeyKES _p
      ]
    ]

eventTracer :: IORef [event] -> Tracer IO event
eventTracer logVar = Tracer (\ev -> liftIO $ atomicModifyIORef' logVar (\acc -> (acc ++ [ev], ())))

matchAllocLog :: [AllocEvent] -> Set WordPtr
matchAllocLog = foldl' (flip go) Set.empty
  where
    go (AllocEv ptr) = Set.insert ptr
    go (FreeEv ptr) = Set.delete ptr
    go (MarkerEv _) = id

testMLockGenKeyKES
  :: forall v.
     KESAlgorithm v
  => Proxy v
  -> Assertion
testMLockGenKeyKES _p = do
  accumVar <- newIORef []
  let tracer = eventTracer accumVar
  let allocator = mkLoggingAllocator tracer mlockedMalloc
  traceWith tracer $ MarkerEv "gen seed"
  seed :: MLockedSeed (SeedSizeKES v) <-
    MLockedSeed <$> mlsbFromByteStringWith allocator (BS.replicate 1024 23)
  traceWith tracer $ MarkerEv "gen key"
  sk <- genKeyKESWith @v allocator seed
  traceWith tracer $ MarkerEv "forget key"
  forgetSignKeyKESWith allocator sk
  traceWith tracer $ MarkerEv "forget seed"
  mlockedSeedFinalize seed
  traceWith tracer $ MarkerEv "done"
  after <- readIORef accumVar
  let evset = matchAllocLog after
  assertBool "some allocations happened" (not . null $ [ () | AllocEv _ <- after ])
  assertEqual "all allocations deallocated" Set.empty evset

{-# NOINLINE testKESAlgorithm#-}
testKESAlgorithm
  :: forall v.
     ( ToCBOR (VerKeyKES v)
     , FromCBOR (VerKeyKES v)
     , EqST (SignKeyKES v)   -- only monadic EqST for signing keys
     , Show (SignKeyKES v) -- fake instance defined locally
     , ToCBOR (SigKES v)
     , FromCBOR (SigKES v)
     , Signable v ~ SignableRepresentation
     , ContextKES v ~ ()
     , UnsoundKESAlgorithm v
     , DirectSerialise IO (SignKeyKES v)
     , DirectSerialise IO (VerKeyKES v)
     , DirectDeserialise IO (SignKeyKES v)
     , DirectDeserialise IO (VerKeyKES v)
     )
  => Lock
  -> String
  -> TestTree
testKESAlgorithm lock n =
  testGroup n
    [ testProperty "only gen signkey" $ prop_onlyGenSignKeyKES @v lock
    , testProperty "only gen verkey" $ prop_onlyGenVerKeyKES @v lock
    , testProperty "one update signkey" $ prop_oneUpdateSignKeyKES @v lock
    , testProperty "all updates signkey" $ prop_allUpdatesSignKeyKES @v lock
    , testProperty "total periods" $ prop_totalPeriodsKES @v lock
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
          ioProperty $ withLock lock $ fmap conjoin $ withAllUpdatesKES @v seedPSB $ \t sk -> do
            prop_no_thunks_IO (signKES () t msg sk)

      , testProperty "VerKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyKES (Proxy @v)) vk
            prop_no_thunks_IO (return $! direct)
      , testProperty "SignKey DirectSerialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyKES (Proxy @v)) sk
            prop_no_thunks_IO (return $! direct)
      , testProperty "VerKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyKES (Proxy @v)) $! vk
            prop_no_thunks_IO (directDeserialiseFromBS @IO @(VerKeyKES v) $! direct)
      , testProperty "SignKey DirectDeserialise" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyKES (Proxy @v)) sk
            bracket
              (directDeserialiseFromBS @IO @(SignKeyKES v) $! direct)
              forgetSignKeyKES
              (prop_no_thunks_IO . return)
      ]

    , testProperty "same VerKey "  $ prop_deriveVerKeyKES @v
    , testProperty "no forgotten chunks in signkey" $ prop_noErasedBlocksInKey (Proxy @v)
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

      , testGroup "DirectSerialise"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              serialized <- directSerialiseToBS (fromIntegral $ sizeVerKeyKES (Proxy @v)) vk
              vk' <- directDeserialiseFromBS serialized
              return $ vk === vk'
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              serialized <- directSerialiseToBS (fromIntegral $ sizeSignKeyKES (Proxy @v)) sk
              equals <- bracket
                          (directDeserialiseFromBS serialized)
                          forgetSignKeyKES
                          (\sk' -> sk ==! sk')
              return $
                counterexample ("Serialized: " ++ hexBS serialized ++ " (length: " ++ show (BS.length serialized) ++ ")") $
                equals
        ]
      , testGroup "DirectSerialise matches raw"
        [ testProperty "VerKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              vk :: VerKeyKES v <- deriveVerKeyKES sk
              direct <- directSerialiseToBS (fromIntegral $ sizeVerKeyKES (Proxy @v)) vk
              let raw = rawSerialiseVerKeyKES vk
              return $ direct === raw
        , testProperty "SignKey" $
            ioPropertyWithSK @v lock $ \sk -> do
              direct <- directSerialiseToBS (fromIntegral $ sizeSignKeyKES (Proxy @v)) sk
              raw <- rawSerialiseSignKeyKES sk
              return $ direct === raw
        ]
      ]

    , testGroup "verify"
      [ testProperty "positive"           $ prop_verifyKES_positive         @v
      , testProperty "negative (key)"     $ prop_verifyKES_negative_key     @v
      , testProperty "negative (message)" $ prop_verifyKES_negative_message @v
      , adjustOption (\(QuickCheckMaxSize sz) -> QuickCheckMaxSize (min sz 50)) $
        testProperty "negative (period)"  $ prop_verifyKES_negative_period  @v
      ]

    , testGroup "serialisation of all KES evolutions"
      [ testProperty "VerKey"  $ prop_serialise_VerKeyKES @v
      , testProperty "Sig"     $ prop_serialise_SigKES    @v
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
withSK :: KESAlgorithm v
       => PinnedSizedBytes (SeedSizeKES v) -> (SignKeyKES v -> IO b) -> IO b
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
ioPropertyWithSK :: forall v a. (Testable a, KESAlgorithm v)
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
--      (KESAlgorithm IO v
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
      KESAlgorithm v
  => Lock -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_onlyGenSignKeyKES lock =
  ioPropertyWithSK @v lock $ const noExceptionsThrown

prop_onlyGenVerKeyKES
  :: forall v.
      KESAlgorithm v
  => Lock -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_onlyGenVerKeyKES lock =
  ioPropertyWithSK @v lock $ doesNotThrow . deriveVerKeyKES

prop_oneUpdateSignKeyKES
  :: forall v.
        ( ContextKES v ~ ()
        , KESAlgorithm v
        )
  => Lock -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_oneUpdateSignKeyKES lock seedPSB =
  ioProperty . withLock lock . withMLockedSeedFromPSB seedPSB $ \seed -> do
    sk <- genKeyKES @v seed
    msk' <- updateKES () sk 0
    forgetSignKeyKES sk
    maybe (return ()) forgetSignKeyKES msk'
    return True

prop_allUpdatesSignKeyKES
  :: forall v.
        ( ContextKES v ~ ()
        , KESAlgorithm v
        )
  => Lock -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_allUpdatesSignKeyKES lock seedPSB =
  ioProperty . withLock lock $ do
    void $ withAllUpdatesKES_ @v seedPSB $ const (return ())

-- | If we start with a signing key, we can evolve it a number of times so that
-- the total number of signing keys (including the initial one) equals the
-- total number of periods for this algorithm.
--
prop_totalPeriodsKES
  :: forall v.
        ( ContextKES v ~ ()
        , KESAlgorithm v
        )
  => Lock -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_totalPeriodsKES lock seed =
    ioProperty . withLock lock $ do
        sks <- withAllUpdatesKES_ @v seed (const . return $ ())
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
  :: forall v.
      ( ContextKES v ~ ()
      , KESAlgorithm v
      )
  => PinnedSizedBytes (SeedSizeKES v) -> Property
prop_deriveVerKeyKES seedPSB =
    ioProperty $ do
        vk_0 <- do
          sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @v
          vk_0 <- deriveVerKeyKES sk_0
          forgetSignKeyKES sk_0
          return vk_0

        vks <- withAllUpdatesKES_ seedPSB deriveVerKeyKES
        return $
          counterexample (show vks) $
          conjoin (map (vk_0 ===) vks)


-- | If we take an initial signing key, a sequence of messages to sign, and
-- sign each one with an updated key, we can verify each one for the
-- corresponding period.
--
prop_verifyKES_positive
  :: forall v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , KESAlgorithm v
     )
  => PinnedSizedBytes (SeedSizeKES v) -> Gen Property
prop_verifyKES_positive seedPSB = do
    xs :: [Message] <- vectorOf totalPeriods arbitrary
    return $ checkCoverage $
      cover 1 (length xs >= totalPeriods) "Message count covers total periods" $
      not (null xs) ==>
      ioProperty $ fmap conjoin $ do
        sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @v
        vk <- deriveVerKeyKES sk_0
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
  :: forall v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , KESAlgorithm v
     )
  => PinnedSizedBytes (SeedSizeKES v)
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_verifyKES_negative_key seedPSB seedPSB' x =
    seedPSB /= seedPSB' ==> ioProperty $ fmap conjoin $ do
        sk_0' <- withMLockedSeedFromPSB seedPSB' $ genKeyKES @v
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
  :: forall v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , KESAlgorithm v
     )
  => PinnedSizedBytes (SeedSizeKES v)
  -> Message -> Message
  -> Property
prop_verifyKES_negative_message seedPSB x x' =
    x /= x' ==> ioProperty $ fmap conjoin $ do
        sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @v
        vk <- deriveVerKeyKES sk_0
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
  :: forall v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , KESAlgorithm v
     )
  => PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_verifyKES_negative_period seedPSB x =
    ioProperty $ fmap conjoin $ do
        sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @v
        vk <- deriveVerKeyKES sk_0
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
  :: forall v.
     ( ContextKES v ~ ()
     , KESAlgorithm v
     )
  => PinnedSizedBytes (SeedSizeKES v)
  -> Property
prop_serialise_VerKeyKES seedPSB =
    ioProperty $ fmap conjoin $ do
        withAllUpdatesKES @v seedPSB $ \t sk -> do
          vk <- deriveVerKeyKES sk
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
  :: forall v.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , Show (SignKeyKES v)
     , KESAlgorithm v
     )
  => PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_serialise_SigKES seedPSB x =
    ioProperty $ fmap conjoin $ do
        withAllUpdatesKES @v seedPSB $ \t sk -> do
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

withAllUpdatesKES_ :: forall v a.
                  ( KESAlgorithm v
                  , ContextKES v ~ ()
                  )
              => PinnedSizedBytes (SeedSizeKES v)
              -> (SignKeyKES v -> IO a)
              -> IO [a]
withAllUpdatesKES_ seedPSB f = do
  withAllUpdatesKES seedPSB (const f)

withAllUpdatesKES :: forall v a.
                  ( KESAlgorithm v
                  , ContextKES v ~ ()
                  )
              => PinnedSizedBytes (SeedSizeKES v)
              -> (Word -> SignKeyKES v -> IO a)
              -> IO [a]
withAllUpdatesKES seedPSB f = withMLockedSeedFromPSB seedPSB $ \seed -> do
  sk_0 <- genKeyKES seed
  go sk_0 0
  where
    go :: SignKeyKES v -> Word -> IO [a]
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

withNullSeed :: forall m n a. (MonadThrow m, MonadST m, KnownNat n) => (MLockedSeed n -> m a) -> m a
withNullSeed = bracket
  (MLockedSeed <$> mlsbFromByteString (BS.replicate (fromIntegral $ natVal (Proxy @n)) 0))
  mlockedSeedFinalize

withNullSK :: forall m v a. (KESAlgorithm v, MonadThrow m, MonadST m)
           => (SignKeyKES v -> m a) -> m a
withNullSK = bracket
  (withNullSeed genKeyKES)
  forgetSignKeyKES


-- | This test detects whether a sign key contains references to pool-allocated
-- blocks of memory that have been forgotten by the time the key is complete.
-- We do this based on the fact that the pooled allocator erases memory blocks
-- by overwriting them with series of 0xff bytes; thus we cut the serialized
-- key up into chunks of 16 bytes, and if any of those chunks is entirely
-- filled with 0xff bytes, we assume that we're looking at erased memory.
prop_noErasedBlocksInKey
  :: forall v.
     UnsoundKESAlgorithm v
  => DirectSerialise IO (SignKeyKES v)
  => Proxy v
  -> Property
prop_noErasedBlocksInKey kesAlgorithm =
  ioProperty . withNullSK @IO @v $ \sk -> do
    let size :: Int = fromIntegral $ sizeSignKeyKES kesAlgorithm
    serialized <- allocaBytes size $ \ptr -> do
      positionVar <- newMVar (0 :: Int)
      directSerialise (\buf nCSize -> do
          let n = fromIntegral nCSize :: Int
          bracket
            (takeMVar positionVar)
            (putMVar positionVar . (+ n))
            (\position -> do
              when (n + position > size) (error "Buffer size exceeded")
              copyMem (plusPtr ptr position) buf (fromIntegral n)
            )
        )
        sk
      packByteStringCStringLen (ptr, size)
    forgetSignKeyKES sk
    return $ counterexample (hexBS serialized) $ not (hasLongRunOfFF serialized)

hasLongRunOfFF :: ByteString -> Bool
hasLongRunOfFF bs
  | BS.length bs < 16
  = False
  | otherwise
  = let first16 = BS.take 16 bs
        remainder = BS.drop 16 bs
    in (BS.all (== 0xFF) first16) || hasLongRunOfFF remainder

