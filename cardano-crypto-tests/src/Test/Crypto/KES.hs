{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE DeriveAnyClass       #-}
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
import Data.Maybe (fromJust)

import Control.Exception (evaluate)
import Control.Concurrent (threadDelay)
import Control.Monad (void)

import Cardano.Crypto.DSIGN hiding (Signable)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES
import Cardano.Crypto.KES.ForgetMock
import Cardano.Crypto.Util (SignableRepresentation(..))
import qualified Cardano.Crypto.Libsodium as NaCl
import qualified Cardano.Crypto.Libsodium.Memory as NaCl
import Cardano.Prelude (ReaderT, runReaderT)
import Cardano.Crypto.SafePinned

import Test.QuickCheck
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckMaxSize(..))
import Test.Tasty.HUnit (testCase)
import Test.HUnit
-- import Debug.Trace (traceShow)

import Test.Crypto.Util hiding (label)
import Test.Crypto.RunIO (RunIO (..))
import Test.Crypto.Instances ()

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.KES"
  [ testKESAlloc (Proxy :: Proxy (SingleKES Ed25519DSIGN)) "SingleKES"
  , testKESAlloc (Proxy :: Proxy (Sum1KES Ed25519DSIGN Blake2b_256)) "Sum1KES"
  , testKESAlgorithm (Proxy :: Proxy IO) (Proxy :: Proxy (MockKES 7))               "MockKES"
  , testKESAlgorithm (Proxy :: Proxy IO) (Proxy :: Proxy (SimpleKES Ed448DSIGN 7))  "SimpleKES"
  , testKESAlgorithm (Proxy :: Proxy IO) (Proxy :: Proxy (SingleKES Ed25519DSIGN))  "SingleKES"
  , testKESAlgorithm (Proxy :: Proxy IO) (Proxy :: Proxy (Sum1KES Ed25519DSIGN Blake2b_256)) "Sum1KES"
  , testKESAlgorithm (Proxy :: Proxy IO) (Proxy :: Proxy (Sum2KES Ed25519DSIGN Blake2b_256)) "Sum2KES"
  , testKESAlgorithm (Proxy :: Proxy IO) (Proxy :: Proxy (Sum5KES Ed25519DSIGN Blake2b_256)) "Sum5KES"
  ]

-- We normally ensure that we avoid naively comparing signing keys by not
-- providing instances, but for tests it is fine, so we provide the orphan
-- instances here.

instance Eq a => Eq (SafePinned a) where
  ap == bp = unsafePerformIO $ do
    interactSafePinned ap $ \a ->
      interactSafePinned bp $ \b ->
        return (a == b)

instance Show (SignKeyKES (SingleKES d)) where
  show _ = "<SignKeySingleKES>"
instance Show (SignKeyKES (SumKES h d)) where
  show _ = "<SignKeySumKES>"

deriving instance Eq (SignKeyDSIGN d) => Eq (SignKeyKES (SimpleKES d t))

deriving instance Eq (NaCl.SodiumSignKeyDSIGN d)
               => Eq (SignKeyKES (SingleKES d))
deriving instance (KESAlgorithm d, NaCl.SodiumHashAlgorithm h, Eq (SignKeyKES d))
               => Eq (SignKeyKES (SumKES h d))

testKESAlloc
  :: forall v proxy.
     ( KESSignAlgorithm IO v
     , ContextKES v ~ ()
     )
  => proxy v
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
  :: forall v proxy.
     ( KESSignAlgorithm IO v
     )
  => proxy v
  -> Assertion
testForgetGenKeyKES _p = do
  let seed = NaCl.mlsbFromByteString (BS.replicate 1024 23)
  logVar <- newIORef []
  let logger str = modifyIORef logVar (++ [str])
  sk <- flip runReaderT logger $ genKeyKES @(ReaderT _ _) @(ForgetMockKES v) seed
  flip runReaderT logger $ forgetSignKeyKES sk
  result <- readIORef logVar
  assertEqual "number of log entries" 2 (length result)
  assertBool "first entry is GEN" ("GEN" `isPrefixOf` (result !! 0))
  assertBool "second entry is DEL" ("DEL" `isPrefixOf` (result !! 1))
  return ()

testForgetUpdateKeyKES
  :: forall v proxy.
     ( KESAlgorithm v
     , KESSignAlgorithm IO v
     , ContextKES v ~ ()
     )
  => proxy v
  -> Assertion
testForgetUpdateKeyKES _p = do
  let seed = NaCl.mlsbFromByteString (BS.replicate 1024 23)
  logVar <- newIORef []
  let logger str = modifyIORef logVar (++ [str])
  sk <- flip runReaderT logger $ genKeyKES @(ReaderT _ _) @(ForgetMockKES v) seed
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


drainAllocLog :: IO [NaCl.AllocEvent]
drainAllocLog =
  reverse <$> go []
  where
    go xs = do
      NaCl.popAllocLogEvent >>= \case
        Nothing ->
          return xs
        Just x ->
          go (x:xs)

matchAllocLog :: [NaCl.AllocEvent] -> Set WordPtr
matchAllocLog evs = foldl' (flip go) Set.empty evs
  where
    go (NaCl.AllocEv ptr) = Set.insert ptr
    go (NaCl.FreeEv ptr) = Set.delete ptr

testMLockGenKeyKES
  :: forall v proxy.
     ( KESAlgorithm v
     , KESSignAlgorithm IO v
     )
  => proxy v
  -> Assertion
testMLockGenKeyKES _p = do
  _ <- drainAllocLog

  (seed :: NaCl.MLockedSizedBytes (SeedSizeKES v)) <- evaluate $ NaCl.mlsbFromByteString (BS.replicate 1024 23)
  sk <- genKeyKES @IO @v seed
  forgetSignKeyKES sk
  NaCl.mlsbFinalize seed
  after <- drainAllocLog
  let evset = matchAllocLog after
  putStrLn ""
  mapM_ print after
  assertEqual "all allocations deallocated" Set.empty evset

testKESAlgorithm
  :: forall m v proxy1 proxy2.
     ( KESAlgorithm v
     , ToCBOR (VerKeyKES v)
     , FromCBOR (VerKeyKES v)
     , Eq (SignKeyKES v)   -- no Eq for signing keys normally
     , Show (SignKeyKES v) -- fake instance defined locally
     , ToCBOR (SigKES v)
     , FromCBOR (SigKES v)
     , Signable v ~ SignableRepresentation
     , ContextKES v ~ ()
     , RunIO m
     , KESSignAlgorithm m v
     , KESSignAlgorithm IO v
     )
  => proxy1 m
  -> proxy2 v
  -> String
  -> TestTree
testKESAlgorithm _pm _pv n =
  testGroup n
    [ testProperty "only gen signkey" $ prop_onlyGenSignKeyKES @v
    , testProperty "only gen verkey" $ prop_onlyGenVerKeyKES @v
    , testProperty "one update signkey" $ prop_oneUpdateSignKeyKES @IO @v Proxy
    , testProperty "all updates signkey" $ prop_allUpdatesSignKeyKES @IO @v Proxy
    , testProperty "total periods" $ prop_totalPeriodsKES @IO @v Proxy
    , testProperty "same VerKey "  $ prop_deriveVerKeyKES @IO @v Proxy
    , testGroup "serialisation"

      [ testGroup "raw ser only"
        [ testProperty "VerKey"  $ prop_raw_serialise_only @(VerKeyKES v)
                                                           rawSerialiseVerKeyKES
        , testProperty "Sig"     $ prop_raw_serialise_only @(SigKES v)
                                                           rawSerialiseSigKES
        , testProperty "SignKey" $ prop_raw_serialise_only @(SignKeyKES v)
                                                           (unsafePerformIO . io . rawSerialiseSignKeyKES @m @v)
        ]
      , testGroup "raw"
        [ testProperty "VerKey"  $ prop_raw_serialise @(VerKeyKES v)
                                                      rawSerialiseVerKeyKES
                                                      rawDeserialiseVerKeyKES
        , testProperty "Sig"     $ prop_raw_serialise @(SigKES v)
                                                      rawSerialiseSigKES
                                                      rawDeserialiseSigKES
        , testProperty "SignKey" $ prop_raw_serialise @(SignKeyKES v)
                                                      (unsafePerformIO . io . rawSerialiseSignKeyKES @m @v)
                                                      (unsafePerformIO . io . rawDeserialiseSignKeyKES @m @v)
        ]

      , testGroup "size"
        [ testProperty "VerKey"  $ prop_size_serialise @(VerKeyKES v)
                                                       rawSerialiseVerKeyKES
                                                       (sizeVerKeyKES (Proxy @ v))
        , testProperty "Sig"     $ prop_size_serialise @(SigKES v)
                                                       rawSerialiseSigKES
                                                       (sizeSigKES (Proxy @ v))
        ]

      , testGroup "direct CBOR"
        [ testProperty "VerKey"  $ prop_cbor_with @(VerKeyKES v)
                                                  encodeVerKeyKES
                                                  decodeVerKeyKES
        , testProperty "Sig"     $ prop_cbor_with @(SigKES v)
                                                  encodeSigKES
                                                  decodeSigKES
        , testProperty "SignKey" $ prop_cbor_with @(SignKeyKES v)
                                                  (unsafePerformIO . io @m . encodeSignKeyKES @v)
                                                  (fromJust . unsafePerformIO . io @m <$> decodeSignKeyKES @v)
        ]

      , testGroup "To/FromCBOR class"
        [ testProperty "VerKey"  $ prop_cbor @(VerKeyKES v)
        , testProperty "Sig"     $ prop_cbor @(SigKES v)
        ]
      , testGroup "ToCBOR size"
        [ testProperty "VerKey"  $ prop_cbor_size @(VerKeyKES v)
        , testProperty "Sig"     $ prop_cbor_size @(SigKES v)
        ]

      , testGroup "direct matches class"
        [ testProperty "VerKey"  $ prop_cbor_direct_vs_class @(VerKeyKES v)
                                                             encodeVerKeyKES
        , testProperty "Sig"     $ prop_cbor_direct_vs_class @(SigKES v)
                                                             encodeSigKES
        ]
      ]

    , testGroup "verify"
      [ testProperty "positive"           $ prop_verifyKES_positive         @IO @v Proxy
      , testProperty "negative (key)"     $ prop_verifyKES_negative_key     @IO @v Proxy
      , testProperty "negative (message)" $ prop_verifyKES_negative_message @IO @v Proxy
      , adjustOption (\(QuickCheckMaxSize sz) -> QuickCheckMaxSize (min sz 50)) $
        testProperty "negative (period)"  $ prop_verifyKES_negative_period  @IO @v Proxy
      ]

    , testGroup "serialisation of all KES evolutions"
      [ testProperty "VerKey"  $ prop_serialise_VerKeyKES  @IO @v Proxy
      , testProperty "Sig"     $ prop_serialise_SigKES     @IO @v Proxy
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyKES v)
      , testProperty "SignKey" $ prop_no_thunks @(SignKeyKES v)
      , testProperty "Sig"     $ prop_no_thunks @(SigKES v)
      ]
    ]


prop_onlyGenSignKeyKES
  :: forall v.
     SignKeyKES v -> Bool
prop_onlyGenSignKeyKES sk =
  sk `seq` True

prop_onlyGenVerKeyKES
  :: forall v.
     VerKeyKES v -> Bool
prop_onlyGenVerKeyKES vk =
  vk `seq` True

prop_oneUpdateSignKeyKES 
  :: forall m v proxy.
        ( ContextKES v ~ ()
        , RunIO m
        , KESSignAlgorithm m v
        )
  => proxy m -> SignKeyKES v -> Property
prop_oneUpdateSignKeyKES _ sk = ioProperty . io $ do
  sk' <- updateKES @m () sk 0
  sk' `seq` return True

prop_allUpdatesSignKeyKES 
  :: forall m v proxy.
        ( ContextKES v ~ ()
        , RunIO m
        , KESSignAlgorithm m v
        )
  => proxy m -> SignKeyKES v -> Property
prop_allUpdatesSignKeyKES _ sk_0 = ioProperty . io $ do
  void $ withAllUpdatesKES_ @m sk_0 $ \sk_n -> sk_n `seq` return ()

-- | If we start with a signing key, we can evolve it a number of times so that
-- the total number of signing keys (including the initial one) equals the
-- total number of periods for this algorithm.
--
prop_totalPeriodsKES
  :: forall m v proxy.
        ( ContextKES v ~ ()
        , RunIO m
        , KESSignAlgorithm m v
        )
  => proxy m -> SignKeyKES v -> Property
prop_totalPeriodsKES _ sk_0 =
    ioProperty $ do
        sks <- io $ withAllUpdatesKES_ @m sk_0 (const . return $ ())
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
  :: forall m v proxy.
      ( ContextKES v ~ ()
      , RunIO m
      , KESSignAlgorithm m v
      )
  => proxy m -> SignKeyKES v -> Property
prop_deriveVerKeyKES _ sk_0 =
    ioProperty $ do
        vk_0 <- io $ deriveVerKeyKES @m sk_0
        vks <- io $ withAllUpdatesKES_ sk_0 $ deriveVerKeyKES @m
        return $
          counterexample (show vks) $
          conjoin (map (vk_0 ===) vks)


-- | If we take an initial signing key, a sequence of messages to sign, and
-- sign each one with an updated key, we can verify each one for the
-- corresponding period.
--
prop_verifyKES_positive
  :: forall m v proxy.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO m
     , KESSignAlgorithm m v
     )
  => proxy m -> SignKeyKES v -> Gen Property
prop_verifyKES_positive _ sk_0 = do
    xs :: [Message] <- vectorOf totalPeriods arbitrary
    return $ checkCoverage $
      cover 1 (length xs >= totalPeriods) "Message count covers total periods" $
      (length xs > 0) ==>
      ioProperty $ fmap conjoin $ io $ do
        vk <- deriveVerKeyKES @m sk_0
        withAllUpdatesKES sk_0 $ \t sk -> do
          let x = (cycle xs) !! (fromIntegral t)
          sig <- signKES () t x sk
          let verResult = verifyKES () vk t x sig
          return $
            counterexample ("period " ++ show t ++ "/" ++ show totalPeriods) $
            verResult === Right ()
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))


-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using a verification key
-- corresponding to a different signing key, then the verification fails.
--
prop_verifyKES_negative_key
  :: forall m v proxy.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , Eq (SignKeyKES v)
     , RunIO m
     , KESSignAlgorithm m v
     )
  => proxy m -> SignKeyKES v -> SignKeyKES v -> Message -> Property
prop_verifyKES_negative_key _ sk_0 sk'_0 x =
    sk_0 /= sk'_0 ==> ioProperty $ fmap conjoin $ io $ do
        _ <- deriveVerKeyKES @m sk_0
        vk' <- deriveVerKeyKES sk'_0
        withAllUpdatesKES sk_0 $ \t sk -> do
          sig <- signKES () t x sk
          let verResult = verifyKES () vk' t x sig
          return $
            counterexample ("period " ++ show t) $
            verResult =/= Right ()

-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature with a message other than @a@, then the
-- verification fails.
--
prop_verifyKES_negative_message
  :: forall m v proxy.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO m
     , KESSignAlgorithm m v
     )
  => proxy m -> SignKeyKES v -> Message -> Message -> Property
prop_verifyKES_negative_message _ sk_0 x x' =
    x /= x' ==> ioProperty $ fmap conjoin $ io $ do
        vk <- deriveVerKeyKES @m sk_0
        withAllUpdatesKES sk_0 $ \t sk -> do
          sig <- signKES () t x sk
          let verResult = verifyKES () vk t x' sig
          return $
            counterexample ("period " ++ show t) $
            verResult =/= Right ()

-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using the right verification
-- key but at a different period than the key used for signing, then the
-- verification fails.
--
prop_verifyKES_negative_period
  :: forall m v proxy.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO m
     , KESSignAlgorithm m v
     )
  => proxy m -> SignKeyKES v -> Message -> Property
prop_verifyKES_negative_period _ sk_0 x =
    ioProperty $ fmap conjoin $ io $ do
        vk <- deriveVerKeyKES @m sk_0
        withAllUpdatesKES sk_0 $ \t sk -> do
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
  :: forall m v proxy.
     ( ContextKES v ~ ()
     , RunIO m
     , KESSignAlgorithm m v
     )
  => proxy m -> SignKeyKES v -> Property
prop_serialise_VerKeyKES _ sk_0 =
    ioProperty $ fmap conjoin $ io $ do
        withAllUpdatesKES sk_0 $ \t sk -> do
          vk <- deriveVerKeyKES @m sk
          return $
                 counterexample ("period " ++ show t) $
                 counterexample ("vkey " ++ show vk) $
                    prop_raw_serialise rawSerialiseVerKeyKES
                                       rawDeserialiseVerKeyKES vk
                .&. prop_cbor_with encodeVerKeyKES
                                   decodeVerKeyKES vk
                .&. prop_size_serialise rawSerialiseVerKeyKES
                                        (sizeVerKeyKES (Proxy @ v)) vk

-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'SigKES' on /all/ the KES key evolutions.
--
prop_serialise_SigKES
  :: forall m v proxy.
     ( ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , Show (SignKeyKES v)
     , RunIO m
     , KESSignAlgorithm m v
     )
  => proxy m -> SignKeyKES v -> Message -> Property
prop_serialise_SigKES _ sk_0 x =
    ioProperty $ fmap conjoin $ io $ do
        withAllUpdatesKES @m sk_0 $ \t sk -> do
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
                                      (sizeSigKES (Proxy @ v)) sig

--
-- KES test utils
--

withAllUpdatesKES_ :: forall m v a.
                  ( KESSignAlgorithm m v
                  , ContextKES v ~ ()
                  )
              => SignKeyKES v
              -> (SignKeyKES v -> m a)
              -> m [a]
withAllUpdatesKES_ sk f =
  withAllUpdatesKES sk (const f)

withAllUpdatesKES :: forall m v a.
                  ( KESSignAlgorithm m v
                  , ContextKES v ~ ()
                  )
              => SignKeyKES v
              -> (Word -> SignKeyKES v -> m a)
              -> m [a]
withAllUpdatesKES sk_0 f =
  go sk_0 0
  where
    go :: SignKeyKES v -> Word -> m [a]
    go sk t = do
      x <- f t sk
      msk' <- x `seq` updateKES () sk t
      case msk' of
        Nothing -> do
          forgetSignKeyKES sk
          return [x]
        Just sk' -> do
          forgetSignKeyKES sk
          xs <- go sk' (t + 1)
          return $ x:xs

--
-- Arbitrary instances
--

instance (KESSignAlgorithm IO v) => Arbitrary (VerKeyKES v) where
  arbitrary = unsafePerformIO . deriveVerKeyKES <$> arbitrary
  shrink = const []

instance (KESSignAlgorithm IO v) => Arbitrary (SignKeyKES v) where
  arbitrary = unsafePerformIO . genKeyKES <$> arbitrary
  shrink = const []

instance ( KESSignAlgorithm IO v
         , ContextKES v ~ ()
         , Signable v ~ SignableRepresentation
         )
      => Arbitrary (SigKES v) where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    let sig = unsafePerformIO $ signKES () 0 a sk
    return sig
  shrink = const []
