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

import Control.Exception (evaluate)
import Control.Concurrent (threadDelay)
import Control.Monad (forM)

import Cardano.Crypto.DSIGN hiding (Signable)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES
import Cardano.Crypto.KES.ForgetMock
import Cardano.Crypto.Util (SignableRepresentation(..))
import qualified Cardano.Crypto.Libsodium as NaCl
import qualified Cardano.Crypto.Libsodium.Memory as NaCl
import Cardano.Prelude (runReaderT, Identity, runIdentity)
import Cardano.Crypto.SafePinned

import Test.QuickCheck
import Test.Tasty (TestTree, testGroup, adjustOption)
import Test.Tasty.QuickCheck (testProperty, QuickCheckMaxSize(..))
import Test.Tasty.HUnit (testCase)
import Test.HUnit
-- import Debug.Trace (traceShow)

import Test.Crypto.Util hiding (label)
import Test.Crypto.Instances ()

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.KES"
  [ testKESAlloc (Proxy :: Proxy (SingleKES Ed25519DSIGN)) "SingleKES"
  , testKESAlloc (Proxy :: Proxy (Sum1KES Ed25519DSIGN Blake2b_256)) "Sum1KES"
  , testKESAlgorithm (Proxy :: Proxy (MockKES 7))               "MockKES"
  , testKESAlgorithm (Proxy :: Proxy (SimpleKES Ed448DSIGN 7))  "SimpleKES"
  , testKESAlgorithm (Proxy :: Proxy (SingleKES Ed25519DSIGN))  "SingleKES"
  , testKESAlgorithm (Proxy :: Proxy (Sum1KES Ed25519DSIGN Blake2b_256)) "Sum1KES"
  , testKESAlgorithm (Proxy :: Proxy (Sum2KES Ed25519DSIGN Blake2b_256)) "Sum2KES"
  , testKESAlgorithm (Proxy :: Proxy (Sum5KES Ed25519DSIGN Blake2b_256)) "Sum5KES"
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
     ( KESAlgorithm v
     , SignKeyAccessKES v ~ IO
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
     ( KESAlgorithm v
     , SignKeyAccessKES v ~ IO
     )
  => proxy v
  -> Assertion
testForgetGenKeyKES _p = do
  let seed = NaCl.mlsbFromByteString (BS.replicate 1024 23)
  logVar <- newIORef []
  let logger str = modifyIORef logVar (++ [str])
  sk <- flip runReaderT logger $ genKeyKES @(ForgetMockKES v) seed
  flip runReaderT logger $ forgetSignKeyKES sk
  result <- readIORef logVar
  assertEqual "number of log entries" 2 (length result)
  assertBool "first entry is GEN" ("GEN" `isPrefixOf` (result !! 0))
  assertBool "second entry is DEL" ("DEL" `isPrefixOf` (result !! 1))
  return ()

testForgetUpdateKeyKES
  :: forall v proxy.
     ( KESAlgorithm v
     , SignKeyAccessKES v ~ IO
     , ContextKES v ~ ()
     )
  => proxy v
  -> Assertion
testForgetUpdateKeyKES _p = do
  let seed = NaCl.mlsbFromByteString (BS.replicate 1024 23)
  logVar <- newIORef []
  let logger str = modifyIORef logVar (++ [str])
  sk <- flip runReaderT logger $ genKeyKES @(ForgetMockKES v) seed
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
  go []
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
     , SignKeyAccessKES v ~ IO
     )
  => proxy v
  -> Assertion
testMLockGenKeyKES _p = do
  seed <- evaluate $ NaCl.mlsbFromByteString (BS.replicate 1024 23)
  _ <- drainAllocLog
  sk <- genKeyKES @v seed
  forgetSignKeyKES sk
  NaCl.mlsbFinalize seed
  after <- drainAllocLog
  let evset = matchAllocLog after
  -- putStrLn "--- before ---"
  -- mapM_ print before
  putStrLn "--- after ---"
  mapM_ print after
  assertEqual "all allocations deallocated" Set.empty evset

testKESAlgorithm
  :: forall v proxy.
     ( KESAlgorithm v
     , ToCBOR (VerKeyKES v)
     , FromCBOR (VerKeyKES v)
     , Eq (SignKeyKES v)   -- no Eq for signing keys normally
     , Show (SignKeyKES v) -- fake instance defined locally
     , ToCBOR (SigKES v)
     , FromCBOR (SigKES v)
     , Signable v ~ SignableRepresentation
     , ContextKES v ~ ()
     , RunIO (SignKeyAccessKES v)
     )
  => proxy v
  -> String
  -> TestTree
testKESAlgorithm _p n =
  testGroup n
    [ testGroup "serialisation"
      [ testGroup "raw"
        [ testProperty "VerKey"  $ prop_raw_serialise @(VerKeyKES v)
                                                      rawSerialiseVerKeyKES
                                                      rawDeserialiseVerKeyKES
        , testProperty "Sig"     $ prop_raw_serialise @(SigKES v)
                                                      rawSerialiseSigKES
                                                      rawDeserialiseSigKES
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

    , testProperty "only gen signkey" $ prop_onlyGenSignKeyKES @v
    , testProperty "one update signkey" $ prop_oneUpdageSignKeyKES @v
    , testProperty "total periods" $ prop_totalPeriodsKES @v
    , testProperty "same VerKey "  $ prop_deriveVerKeyKES @v

    , testGroup "verify"
      [ testProperty "positive"           $ prop_verifyKES_positive         @v
      , testProperty "negative (key)"     $ prop_verifyKES_negative_key     @v
      , testProperty "negative (message)" $ prop_verifyKES_negative_message @v
      , adjustOption (\(QuickCheckMaxSize sz) -> QuickCheckMaxSize (min sz 50)) $
        testProperty "negative (period)"  $ prop_verifyKES_negative_period  @v
      ]

    , testGroup "serialisation of all KES evolutions"
      [ testProperty "VerKey"  $ prop_serialise_VerKeyKES  @v
      , testProperty "Sig"     $ prop_serialise_SigKES     @v
      ]

    , testGroup "NoThunks"
      [ testProperty "VerKey"  $ prop_no_thunks @(VerKeyKES v)
      , testProperty "SignKey" $ prop_no_thunks @(SignKeyKES v)
      , testProperty "Sig"     $ prop_no_thunks @(SigKES v)
      ]
    ]


prop_onlyGenSignKeyKES
  :: forall v.
        ( KESAlgorithm v
        , ContextKES v ~ ()
        , RunIO (SignKeyAccessKES v)
        )
  => SignKeyKES v -> Bool
prop_onlyGenSignKeyKES sk =
  sk `seq` True

prop_oneUpdageSignKeyKES 
  :: forall v.
        ( KESAlgorithm v
        , ContextKES v ~ ()
        , Show (SignKeyKES v)
        , RunIO (SignKeyAccessKES v)
        )
  => SignKeyKES v -> Property
prop_oneUpdageSignKeyKES sk = ioProperty . io $ do
  sk' <- updateKES () sk 0
  sk' `seq` return True
  

-- | If we start with a signing key, we can evolve it a number of times so that
-- the total number of signing keys (including the initial one) equals the
-- total number of periods for this algorithm.
--
prop_totalPeriodsKES
  :: forall v.
        ( KESAlgorithm v
        , ContextKES v ~ ()
        , Show (SignKeyKES v)
        , RunIO (SignKeyAccessKES v)
        )
  => SignKeyKES v -> Property
prop_totalPeriodsKES sk_0 =
    ioProperty $ do
        sks <- io $ allUpdatesKES sk_0
        return $
          totalPeriods > 0 ==>
          counterexample (show totalPeriods) $
          counterexample (show sks) $
          length sks === totalPeriods
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))


-- | If we start with a signing key, and all its evolutions, the verification
-- keys we derive from each one are the same.
--
prop_deriveVerKeyKES
  :: forall v. (KESAlgorithm v, ContextKES v ~ (), RunIO (SignKeyAccessKES v))
  => SignKeyKES v -> Property
prop_deriveVerKeyKES sk_0 =
    ioProperty $ do
        sks <- io $ allUpdatesKES sk_0
        vk_0 <- io $ deriveVerKeyKES sk_0
        vks <- io $ mapM deriveVerKeyKES sks
        return $
          counterexample (show vks) $
          conjoin (map (vk_0 ===) vks)


-- | If we take an initial signing key, a sequence of messages to sign, and
-- sign each one with an updated key, we can verify each one for the
-- corresponding period.
--
prop_verifyKES_positive
  :: forall v.
     ( KESAlgorithm v
     , ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO (SignKeyAccessKES v)
     )
  => SignKeyKES v -> [Message] -> Property
prop_verifyKES_positive sk_0 xs =
    ioProperty $ do
        sks <- io $ allUpdatesKES sk_0
        vk <- io $ deriveVerKeyKES sk_0
        txsks <- forM (zip3 [0..] xs sks) $ \(t, x, sk) -> do
            sig <- io $ signKES () t x sk
            return (t, x, sk, sig)
        return $
            cover 1 (length xs >= totalPeriods) "covers total periods" $
            conjoin [ counterexample ("period " ++ show t) $
                      verifyKES () vk t x sig === Right ()
                    | (t, x, sk, sig) <- txsks
                    ]
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral (totalPeriodsKES (Proxy :: Proxy v))


-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using a verification key
-- corresponding to a different signing key, then the verification fails.
--
prop_verifyKES_negative_key
  :: forall v.
     ( KESAlgorithm v
     , ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , Eq (SignKeyKES v)
     , RunIO (SignKeyAccessKES v)
     )
  => SignKeyKES v -> SignKeyKES v -> Message -> Property
prop_verifyKES_negative_key sk_0 sk'_0 x =
    sk_0 /= sk'_0 ==> ioProperty $ do
        sks <- io $ allUpdatesKES sk_0
        vk' <- io $ deriveVerKeyKES sk'_0
        tsks <- forM (zip [0..] sks) $ \(t, sk) -> do
            sig <- io $ signKES () t x sk
            return (t, sk, sig)
        return $
            conjoin [ counterexample ("period " ++ show t) $
                      verifyKES () vk' t x sig =/= Right ()
                    | (t, sk, sig) <- tsks
                    ]

-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature with a message other than @a@, then the
-- verification fails.
--
prop_verifyKES_negative_message
  :: forall v.
     ( KESAlgorithm v
     , ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO (SignKeyAccessKES v)
     )
  => SignKeyKES v -> Message -> Message -> Property
prop_verifyKES_negative_message sk_0 x x' =
    x /= x' ==> ioProperty $ do
        sks <- io $ allUpdatesKES sk_0
        vk <- io $ deriveVerKeyKES sk_0
        tsks <- forM (zip [0..] sks) $ \(t, sk) -> do
            sig <- io $ signKES () t x sk
            return (t, sk, sig)
        return $
            conjoin [ counterexample ("period " ++ show t) $
                      verifyKES () vk t x' sig =/= Right ()
                    | (t, sk, sig) <- tsks
                    ]

-- | If we sign a message @a@ with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using the right verification
-- key but at a different period than the key used for signing, then the
-- verification fails.
--
prop_verifyKES_negative_period
  :: forall v.
     ( KESAlgorithm v
     , ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO (SignKeyAccessKES v)
     )
  => SignKeyKES v -> Message -> Property
prop_verifyKES_negative_period sk_0 x =
    ioProperty $ do
        sks <- io $ allUpdatesKES sk_0
        vk <- io $ deriveVerKeyKES sk_0
        tsks <- forM (zip [0..] sks) $ \(t, sk) -> do
            sig <- io $ signKES () t x sk
            return (t, sk, sig)
        return $
            conjoin [ counterexample ("periods " ++ show (t, t')) $
                      verifyKES () vk t' x sig =/= Right ()
                    | (t, sk, sig) <- tsks
                    , (t', _) <- zip [0..] sks
                    , t /= t'
                    ]


-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'VerKeyKES' on /all/ the KES key evolutions.
--
prop_serialise_VerKeyKES
  :: forall v.
     ( KESAlgorithm v
     , ContextKES v ~ ()
     , RunIO (SignKeyAccessKES v)
     )
  => SignKeyKES v -> Property
prop_serialise_VerKeyKES sk_0 =
    ioProperty $ do
        vks <- io $ mapM deriveVerKeyKES =<< allUpdatesKES sk_0
        return $
            conjoin
              [ counterexample ("period " ++ show (t :: Int)) $
                counterexample ("vkey " ++ show vk) $
                   prop_raw_serialise rawSerialiseVerKeyKES
                                      rawDeserialiseVerKeyKES vk
               .&. prop_cbor_with encodeVerKeyKES
                                  decodeVerKeyKES vk
               .&. prop_size_serialise rawSerialiseVerKeyKES
                                       (sizeVerKeyKES (Proxy @ v)) vk
              | (t, vk) <- zip [0..] vks
              ]


-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'SigKES' on /all/ the KES key evolutions.
--
prop_serialise_SigKES
  :: forall v.
     ( KESAlgorithm v
     , ContextKES v ~ ()
     , Signable v ~ SignableRepresentation
     , RunIO (SignKeyAccessKES v)
     , Show (SignKeyKES v)
     )
  => SignKeyKES v -> Message -> Property
prop_serialise_SigKES sk_0 x =
    ioProperty $ do
        tsks <- io $ do
            sks <- allUpdatesKES sk_0
            forM (zip [0..] sks) $ \(t, sk) -> do
                sig <- signKES () t x sk
                return (t, sk, sig)
        return $
            conjoin
              [ counterexample ("period " ++ show t) $
                counterexample ("vkey "   ++ show sk) $
                counterexample ("sig "    ++ show sig) $
                   prop_raw_serialise rawSerialiseSigKES
                                      rawDeserialiseSigKES sig
               .&. prop_cbor_with encodeSigKES
                                  decodeSigKES sig
               .&. prop_size_serialise rawSerialiseSigKES
                                       (sizeSigKES (Proxy @ v)) sig
              | (t, sk, sig) <- tsks
              ]

--
-- KES test utils
--

allUpdatesKES :: forall v.
                  ( KESAlgorithm v
                  , ContextKES v ~ ()
                  )
              => SignKeyKES v
              -> SignKeyAccessKES v [SignKeyKES v]
allUpdatesKES sk_0 =
    (sk_0 :) <$> unfoldrM update (sk_0, 0)
  where
    update :: (SignKeyKES v, Period)
           -> SignKeyAccessKES v (Maybe (SignKeyKES v, (SignKeyKES v, Period)))
    update (sk, t) = do
      updateKES () sk t >>= \case
        Nothing  -> return Nothing
        Just sk' -> sk' `seq` return $ Just (sk', (sk', t+1))

unfoldrM :: Monad m => (b -> m (Maybe (a, b))) -> b -> m [a]
unfoldrM f x = do
  my <- f x
  case my of
    Nothing -> return []
    Just (y, x') -> do
      ys <- unfoldrM f x'
      return (y:ys)

--
-- Arbitrary instances
--

instance (KESAlgorithm v, RunIO (SignKeyAccessKES v)) => Arbitrary (VerKeyKES v) where
  arbitrary = unsafePerformIO . io . deriveVerKeyKES <$> arbitrary
  shrink = const []

instance (KESAlgorithm v, RunIO (SignKeyAccessKES v)) => Arbitrary (SignKeyKES v) where
  arbitrary = unsafePerformIO . io . genKeyKES <$> arbitrary
  shrink = const []

instance ( KESAlgorithm v
         , ContextKES v ~ ()
         , Signable v ~ SignableRepresentation
         , RunIO (SignKeyAccessKES v)
         )
      => Arbitrary (SigKES v) where
  arbitrary = do
    a <- arbitrary :: Gen Message
    sk <- arbitrary
    let sig = unsafePerformIO . io $ signKES () 0 a sk
    return sig
  shrink = const []

class RunIO m where
  io :: m a -> IO a

instance RunIO IO where
  io = id

instance RunIO Identity where
  io = return . runIdentity
