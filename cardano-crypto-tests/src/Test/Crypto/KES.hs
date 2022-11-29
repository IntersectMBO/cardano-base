{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE DeriveAnyClass       #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE LambdaCase           #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE StandaloneDeriving   #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}

{-# OPTIONS_GHC -Wno-orphans #-}

module Test.Crypto.KES
  ( tests
  )
where

import Data.Proxy (Proxy(..))
import Data.List (isPrefixOf, foldl')
import qualified Data.ByteString as BS
import Data.Set (Set)
import qualified Data.Set as Set
import Foreign.Ptr (WordPtr)
import System.IO.Unsafe (unsafePerformIO)
import Data.IORef
import Text.Printf

import Control.Concurrent (threadDelay)
import Control.Monad (void)
import Control.Monad.IO.Class (MonadIO)

import Cardano.Crypto.DSIGN hiding (Signable)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES
import Cardano.Crypto.KES.ForgetMock
import Cardano.Crypto.Util (SignableRepresentation(..))
import qualified Cardano.Crypto.Libsodium as NaCl
import qualified Cardano.Crypto.Libsodium.Memory as NaCl
import Cardano.Prelude (ReaderT, runReaderT, evaluate, bracket)
import Cardano.Crypto.SafePinned
import Cardano.Crypto.PinnedSizedBytes (PinnedSizedBytes)

import Test.QuickCheck
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckMaxSize(..))
import Test.Tasty.HUnit (testCase)
import Test.HUnit
-- import Debug.Trace (traceShow)

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
  -- prop_no_thunks,
  arbitrarySeedBytesOfSize,
  Lock, withLock,
  )
import Test.Crypto.RunIO (RunIO (..))
import Test.Crypto.Instances (withMLSBFromPSB)

{- HLINT ignore "Reduce duplication" -}

--
-- The list of all tests
--
tests :: Lock -> TestTree
tests lock =
  testGroup "Crypto.KES"
  [ testKESAlloc lock (Proxy :: Proxy (SingleKES Ed25519DSIGNM)) "SingleKES"
  , testKESAlloc lock (Proxy :: Proxy (Sum1KES Ed25519DSIGNM Blake2b_256)) "Sum1KES"
  , testKESAlloc lock (Proxy :: Proxy (Sum2KES Ed25519DSIGNM Blake2b_256)) "Sum2KES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (MockKES 7))               "MockKES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (SimpleKES Ed448DSIGN 7))  "SimpleKES"
  , testKESAlgorithm lock (Proxy :: Proxy IO) (Proxy :: Proxy (SingleKES Ed25519DSIGNM))  "SingleKES"
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

instance Eq a => Eq (SafePinned a) where
  ap == bp = unsafePerformIO $ do
    interactSafePinned ap $ \a ->
      interactSafePinned bp $ \b ->
        return (a == b)

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

hexBS :: ByteString -> String
hexBS = concatMap (printf "%02x") . BS.unpack

deriving instance Eq (SignKeyDSIGN d) => Eq (SignKeyKES (SimpleKES d t))

deriving instance Eq (SignKeyDSIGNM d)
               => Eq (SignKeyKES (SingleKES d))
deriving instance (KESAlgorithm d, NaCl.SodiumHashAlgorithm h, Eq (SignKeyKES d))
               => Eq (SignKeyKES (SumKES h d))
deriving instance Eq (SignKeyDSIGNM d)
               => Eq (SignKeyKES (CompactSingleKES d))
deriving instance (KESAlgorithm d, Eq (SignKeyKES d))
               => Eq (SignKeyKES (CompactSumKES h d))

testKESAlloc
  :: forall v.
     ( KESSignAlgorithm IO v
     , ContextKES v ~ ()
     )
  => Lock
  -> Proxy v
  -> String
  -> TestTree
testKESAlloc lock _p n =
  testGroup n
    [ testGroup "Forget mock"
      [ testCase "genKey" $ testForgetGenKeyKES lock _p
      , testCase "updateKey" $ testForgetUpdateKeyKES lock _p
      ]
    , testGroup "Low-level mlocked allocations"
      [ testCase "genKey" $ testMLockGenKeyKES lock _p
      -- , testCase "updateKey" $ testMLockUpdateKeyKES lock _p
      ]
    ]

testForgetGenKeyKES
  :: forall v.
     ( KESSignAlgorithm IO v
     )
  => Lock
  -> Proxy v
  -> Assertion
testForgetGenKeyKES lock _p = withLock lock $ do
  seed <- NaCl.mlsbFromByteString (BS.replicate 1024 23)
  logVar <- newIORef []
  let logger str = modifyIORef logVar (++ [str])
  sk <- flip runReaderT logger $ genKeyKES @(ReaderT _ _) @(ForgetMockKES v) seed
  NaCl.mlsbFinalize seed
  flip runReaderT logger $ do
    forgetSignKeyKES sk
  result <- readIORef logVar
  assertEqual "number of log entries" 2 (length result)
  assertBool "first entry is GEN" ("GEN" `isPrefixOf` (result !! 0))
  assertBool "second entry is DEL" ("DEL" `isPrefixOf` (result !! 1))
  return ()

testForgetUpdateKeyKES
  :: forall v.
     ( KESSignAlgorithm IO v
     , ContextKES v ~ ()
     )
  => Lock
  -> Proxy v
  -> Assertion
testForgetUpdateKeyKES lock _p = withLock lock $ do
  seed <- NaCl.mlsbFromByteString (BS.replicate 1024 23)
  logVar <- newIORef []
  let logger str = modifyIORef logVar (++ [str])
  sk <- flip runReaderT logger $ genKeyKES @(ReaderT _ _) @(ForgetMockKES v) seed
  NaCl.mlsbFinalize seed
  msk' <- flip runReaderT logger $ updateKES () sk 0
  case msk' of
    Just sk' -> flip runReaderT logger $ forgetSignKeyKES sk'
    Nothing -> return ()
  threadDelay 1000000
  result <- readIORef logVar
  -- assertEqual "number of log entries" 3 (length result)
  assertBool "first entry is GEN" ("GEN" `isPrefixOf` (result !! 0))
  -- assertBool "second entry is UPD" ("UPD" `isPrefixOf` (result !! 1))
  -- assertBool "third entry is DEL" ("DEL" `isPrefixOf` (result !! 2))


matchAllocLog :: [NaCl.AllocEvent] -> Set WordPtr
matchAllocLog evs = foldl' (flip go) Set.empty evs
  where
    go (NaCl.AllocEv ptr) = Set.insert ptr
    go (NaCl.FreeEv ptr) = Set.delete ptr
    go (NaCl.MarkerEv _) = id

testMLockGenKeyKES
  :: forall v.
     ( KESSignAlgorithm IO v
     )
  => Lock
  -> Proxy v
  -> Assertion
testMLockGenKeyKES lock _p = withLock lock $ do
  after <- NaCl.withAllocLog $ do
    NaCl.pushAllocLogEvent $ NaCl.MarkerEv "gen seed"
    (seed :: NaCl.MLockedSizedBytes (SeedSizeKES v)) <- NaCl.mlsbFromByteString (BS.replicate 1024 23)
    NaCl.pushAllocLogEvent $ NaCl.MarkerEv "gen key"
    sk <- genKeyKES @IO @v seed
    NaCl.pushAllocLogEvent $ NaCl.MarkerEv "forget key"
    forgetSignKeyKES sk
    NaCl.pushAllocLogEvent $ NaCl.MarkerEv "forget seed"
    NaCl.mlsbFinalize seed
    NaCl.pushAllocLogEvent $ NaCl.MarkerEv "done"
  let evset = matchAllocLog after
  putStrLn ""
  mapM_ print after
  assertEqual "all allocations deallocated" Set.empty evset

testKESAlgorithm
  :: forall m v.
     ( ToCBOR (VerKeyKES v)
     , FromCBOR (VerKeyKES v)
     , Eq (SignKeyKES v)   -- no Eq for signing keys normally
     , Show (SignKeyKES v) -- fake instance defined locally
     , ToCBOR (SigKES v)
     , FromCBOR (SigKES v)
     , Signable v ~ SignableRepresentation
     , ContextKES v ~ ()
     , KESSignAlgorithm m v
     , KESSignAlgorithm IO v
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
    , testProperty "same VerKey "  $ prop_deriveVerKeyKES lock (Proxy @IO) (Proxy @v)
    , testProperty "no forgotten chunks in signkey" $ prop_noErasedBlocksInKey lock (Proxy @v)
    , testGroup "serialisation"

      [ testGroup "raw ser only"
        [ testProperty "VerKey" $
            ioProperty . withLock lock $ do
              vk :: VerKeyKES v <- withNewTestSK deriveVerKeyKES
              return $ (rawDeserialiseVerKeyKES . rawSerialiseVerKeyKES $ vk) === Just vk
        , testProperty "SignKey" $
            ioProperty . withLock lock . withNewTestSK $ \sk -> do
              serialized <- rawSerialiseSignKeyKES sk
              msk' <- rawDeserialiseSignKeyKES serialized
              equals <- evaluate (Just sk == msk')
              maybe (return ()) forgetSignKeyKES msk'
              return equals
        , testProperty "Sig" $ property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock $ do
              sig :: SigKES v <- withNewTestSK (signKES () 0 msg)
              return $ (rawDeserialiseSigKES . rawSerialiseSigKES $ sig) === Just sig
        ]
      , testGroup "size"
        [ testProperty "VerKey"  $
            ioProperty . withLock lock $ do
              vk :: VerKeyKES v <- withNewTestSK deriveVerKeyKES
              return $ (fromIntegral . BS.length . rawSerialiseVerKeyKES $ vk) === (sizeVerKeyKES (Proxy @v))
        , testProperty "SignKey" $
            ioProperty . withLock lock . withNewTestSK $ \sk -> do
              serialized <- rawSerialiseSignKeyKES sk
              equals <- evaluate ((fromIntegral . BS.length $ serialized) == (sizeSignKeyKES (Proxy @v)))
              return equals
        , testProperty "Sig" $ property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock $ do
              sig :: SigKES v <- withNewTestSK (signKES () 0 msg)
              return $ (fromIntegral . BS.length . rawSerialiseSigKES $ sig) === (sizeSigKES (Proxy @v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey" $
            ioProperty . withLock lock $ do
              vk :: VerKeyKES v <- withNewTestSK deriveVerKeyKES
              return $ prop_cbor_with encodeVerKeyKES decodeVerKeyKES vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock $ do
              sig :: SigKES v <- withNewTestSK (signKES () 0 msg)
              return $ prop_cbor_with encodeSigKES decodeSigKES sig
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $
              ioProperty . withLock lock $ do
                vk :: VerKeyKES v <- withNewTestSK deriveVerKeyKES
                return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyKES', see above.
        , testProperty "Sig" $ property $ do
              msg <- mkMsg
              return . ioProperty . withLock lock $ do
                sig :: SigKES v <- withNewTestSK (signKES () 0 msg)
                return $ prop_cbor sig
        ]

      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $
              ioProperty . withLock lock $ do
                vk :: VerKeyKES v <- withNewTestSK deriveVerKeyKES
                return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyKES', see above.
        , testProperty "Sig" $ property $ do
              msg <- mkMsg
              return . ioProperty . withLock lock $ do
                sig :: SigKES v <- withNewTestSK (signKES () 0 msg)
                return $ prop_cbor_size sig
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey" $
            ioProperty . withLock lock $ do
              vk :: VerKeyKES v <- withNewTestSK deriveVerKeyKES
              return $ prop_cbor_direct_vs_class encodeVerKeyKES vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        , testProperty "Sig" $ property $ do
            msg <- mkMsg
            return . ioProperty . withLock lock $ do
              sig :: SigKES v <- withNewTestSK (signKES () 0 msg)
              return $ prop_cbor_direct_vs_class encodeSigKES sig
        ]
      ]

    , testGroup "verify"
      [ testProperty "positive"           $ prop_verifyKES_positive         @IO @v lock Proxy Proxy
      , testProperty "negative (key)"     $ prop_verifyKES_negative_key     @IO @v lock Proxy Proxy
      , testProperty "negative (message)" $ prop_verifyKES_negative_message @IO @v lock Proxy Proxy
      , adjustOption (\(QuickCheckMaxSize sz) -> QuickCheckMaxSize (min sz 50)) $
        testProperty "negative (period)"  $ prop_verifyKES_negative_period  @IO @v lock Proxy Proxy
      ]

    , testGroup "serialisation of all KES evolutions"
      [ testProperty "VerKey"  $ prop_serialise_VerKeyKES  @IO @v lock Proxy Proxy
      , testProperty "Sig"     $ prop_serialise_SigKES     @IO @v lock Proxy Proxy
      ]

    -- TODO: this doesn't pass right now, see
    -- 'prop_key_overwritten_after_forget' for details.
    --
    -- , testGroup "forgetting"
    --   [ testProperty "key overwritten after forget" $ prop_key_overwritten_after_forget lock (Proxy @v)
    --   ]

    -- , testGroup "NoThunks"
    --   [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyKES v)
    --   , testProperty "SignKey" $ prop_no_thunks @(SignKeyKES v)
    --   , testProperty "Sig"     $ prop_no_thunks @(SigKES v)
    --   ]
    ]
  where

    mkMsg :: Gen Message
    mkMsg = arbitrary

    withTestSeedMLSB :: forall a. (NaCl.MLockedSizedBytes (SeedSizeKES v) -> IO a) -> IO a
    withTestSeedMLSB action =
      bracket
        (NaCl.mlsbFromByteString =<< generate (arbitrarySeedBytesOfSize (seedSizeKES (Proxy :: Proxy v))))
        NaCl.mlsbFinalize
        action

    withNewTestSK :: forall a. (SignKeyKES v -> IO a) -> IO a
    withNewTestSK action =
      bracket
        (withTestSeedMLSB genKeyKES)
        forgetSignKeyKES
        action

-- TODO: This doesn't actually pass right now, for various reasons:
-- - MockKES and SimpleKES don't actually implement secure forgetting;
--   forgetSignKeyKES is a no-op for these algorithms, and obviously that means
--   forgetting won't actually erase the key
-- - SumKES and CompactSumKES use a SafePinned guard around the @r@ member,
--   which triggers a 'SafePinnedFinalizedError' if we try to serialize the
--   compound key after forgetting it.
-- prop_key_overwritten_after_forget
--   :: forall v.
--      (KESSignAlgorithm IO v
--      )
--   => Lock
--   -> Proxy v
--   -> PinnedSizedBytes (SeedSizeKES v)
--   -> Property
-- prop_key_overwritten_after_forget lock _ seedPSB =
--   ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
--     sk <- genKeyKES @IO @v seed
--
--     before <- rawSerialiseSignKeyKES sk
--     forgetSignKeyKES sk
--     after <- rawSerialiseSignKeyKES sk
--
--     NaCl.mlsbFinalize seed
--
--     return (before =/= after)


-- | This test detects whether a sign key contains references to pool-allocated
-- blocks of memory that have been forgotten by the time the key is complete.
-- We do this based on the fact that the pooled allocator erases memory blocks
-- by overwriting them with series of 0xff bytes; thus we cut the serialized
-- key up into chunks of 16 bytes, and if any of those chunks is entirely
-- filled with 0xff bytes, we assume that we're looking at erased memory.
prop_noErasedBlocksInKey
  :: forall v.
     KESSignAlgorithm IO v
  -- => Lock -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
  -- prop_noErasedBlocksInKey lock _ seedPSB =
  => Lock -> Proxy v -> Property
prop_noErasedBlocksInKey lock _ =
  ioProperty . withLock lock $ do
    seed <- NaCl.mlsbFromByteString $ BS.replicate 1024 0
    sk <- genKeyKES @IO @v seed
    NaCl.mlsbFinalize seed
    serialized <- rawSerialiseSignKeyKES sk
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

prop_onlyGenSignKeyKES
  :: forall v.
      KESSignAlgorithm IO v
  => Lock -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_onlyGenSignKeyKES lock _ seedPSB =
  ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
    sk <- genKeyKES @IO @v seed
    forgetSignKeyKES sk
    return True

prop_onlyGenVerKeyKES
  :: forall v.
      KESSignAlgorithm IO v
  => Lock -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_onlyGenVerKeyKES lock _ seedPSB = ioProperty . withLock lock . withMLSBFromPSB seedPSB $ \seed -> do
  sk <- genKeyKES @IO @v seed
  _ <- deriveVerKeyKES sk
  forgetSignKeyKES sk
  return True

prop_oneUpdateSignKeyKES
  :: forall m v.
        ( ContextKES v ~ ()
        , RunIO m
        , MonadFail m
        , MonadIO m
        , KESSignAlgorithm m v
        )
  => Lock -> Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_oneUpdateSignKeyKES lock _ _ seedPSB = ioProperty . withLock lock . io . withMLSBFromPSB seedPSB $ \seed -> do
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
        , KESSignAlgorithm m v
        )
  => Lock -> Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_allUpdatesSignKeyKES lock _ _ seedPSB = ioProperty . withLock lock . io $ do
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
      , KESSignAlgorithm m v
      )
  => Lock -> Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Property
prop_deriveVerKeyKES lock _ _ seedPSB =
    ioProperty . withLock lock $ do
        vk_0 <- io $ do
          sk_0 <- withMLSBFromPSB seedPSB $ genKeyKES @m @v
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
     , KESSignAlgorithm m v
     )
  => Lock -> Proxy m -> Proxy v -> PinnedSizedBytes (SeedSizeKES v) -> Gen Property
prop_verifyKES_positive lock _ _ seedPSB = do
    xs :: [Message] <- vectorOf totalPeriods arbitrary
    return $ checkCoverage $
      cover 1 (length xs >= totalPeriods) "Message count covers total periods" $
      (length xs > 0) ==>
      ioProperty $ fmap conjoin $ withLock lock $ io $ do
        sk_0 <- withMLSBFromPSB seedPSB $ genKeyKES @m @v
        vk <- deriveVerKeyKES @m sk_0
        forgetSignKeyKES sk_0
        withAllUpdatesKES seedPSB $ \t sk -> do
          let x = (cycle xs) !! (fromIntegral t)
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
     , KESSignAlgorithm m v
     )
  => Lock -> Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_verifyKES_negative_key lock _ _ seedPSB seedPSB' x =
    seedPSB /= seedPSB' ==> ioProperty $ fmap conjoin $ withLock lock $ io $ do
        sk_0' <- withMLSBFromPSB seedPSB' $ genKeyKES @m @v
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
     , KESSignAlgorithm m v
     )
  => Lock -> Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message -> Message
  -> Property
prop_verifyKES_negative_message lock _ _ seedPSB x x' =
    x /= x' ==> ioProperty $ fmap conjoin $ withLock lock $ io $ do
        sk_0 <- withMLSBFromPSB seedPSB $ genKeyKES @m @v
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
     , KESSignAlgorithm m v
     )
  => Lock -> Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_verifyKES_negative_period lock _ _ seedPSB x =
    ioProperty $ fmap conjoin $ withLock lock $ io $ do
        sk_0 <- withMLSBFromPSB seedPSB $ genKeyKES @m @v
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
     , KESSignAlgorithm m v
     )
  => Lock -> Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Property
prop_serialise_VerKeyKES lock _ _ seedPSB =
    ioProperty $ fmap conjoin $ withLock lock $ io $ do
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
     , KESSignAlgorithm m v
     )
  => Lock -> Proxy m -> Proxy v
  -> PinnedSizedBytes (SeedSizeKES v)
  -> Message
  -> Property
prop_serialise_SigKES lock _ _ seedPSB x =
    ioProperty $ fmap conjoin $ withLock lock $ io $ do
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
                  , MonadIO m
                  , RunIO m
                  )
              => PinnedSizedBytes (SeedSizeKES v)
              -> (SignKeyKES v -> m a)
              -> m [a]
withAllUpdatesKES_ seedPSB f = do
  withAllUpdatesKES seedPSB (const f)

withAllUpdatesKES :: forall m v a.
                  ( KESSignAlgorithm m v
                  , ContextKES v ~ ()
                  , MonadIO m
                  , RunIO m
                  )
              => PinnedSizedBytes (SeedSizeKES v)
              -> (Word -> SignKeyKES v -> m a)
              -> m [a]
withAllUpdatesKES seedPSB f = withMLSBFromPSB seedPSB $ \seed -> do
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

