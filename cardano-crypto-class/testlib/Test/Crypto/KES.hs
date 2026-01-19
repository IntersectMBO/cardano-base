{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE QuantifiedConstraints #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

{- HLINT ignore "Use head" -}

module Test.Crypto.KES (
  tests,
)
where

import qualified Data.ByteString as BS
import qualified Data.Foldable as F (foldl')
import Data.IORef
import Data.Proxy (Proxy (..))
import Data.Set (Set)
import qualified Data.Set as Set
import Foreign.Ptr (WordPtr)
import GHC.TypeNats (KnownNat, Nat, natVal)

import Control.Monad (void)
import Control.Monad.Class.MonadST
import Control.Monad.Class.MonadThrow
import Control.Monad.IO.Class (liftIO)
import Control.Tracer

import Cardano.Crypto.DSIGN hiding (Signable)
import Cardano.Crypto.DirectSerialise (DirectDeserialise, DirectSerialise)
import Cardano.Crypto.Hash
import Cardano.Crypto.KES
import Cardano.Crypto.Libsodium
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.PinnedSizedBytes
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.Crypto.Util (SignableRepresentation (..))

import Test.Hspec (Expectation, Spec, describe, it, shouldSatisfy)
import Test.Hspec.QuickCheck (modifyMaxSuccess, prop)
import Test.QuickCheck

import Test.Crypto.AllocLog
import Test.Crypto.EqST
import Test.Crypto.Instances (withMLockedSeedFromPSB)
import Test.Crypto.Util (
  FromCBOR,
  Lock,
  Message,
  ToCBOR,
  directDeserialiseFromBS,
  directSerialiseToBS,
  doesNotThrow,
  hexBS,
  noExceptionsThrown,
  prop_cbor,
  prop_cbor_direct_vs_class,
  prop_cbor_size,
  prop_cbor_with,
  prop_no_thunks_IO,
  prop_raw_serialise,
  prop_size_serialise,
  withLock,
 )

{- HLINT ignore "Reduce duplication" -}
{- HLINT ignore "Use head" -}

--
-- The list of all tests
--
tests :: Lock -> Spec
tests lock =
  describe "Crypto.KES" $ do
    testKESAlloc (Proxy @(SingleKES Ed25519DSIGN)) "SingleKES"
    testKESAlloc (Proxy @(Sum1KES Ed25519DSIGN Blake2b_256)) "Sum1KES"
    testKESAlloc (Proxy @(Sum2KES Ed25519DSIGN Blake2b_256)) "Sum2KES"
    testKESAlgorithm @(MockKES 7) lock "MockKES"
    testKESAlgorithm @(SimpleKES Ed25519DSIGN 7) lock "SimpleKES"
    testKESAlgorithm @(SingleKES Ed25519DSIGN) lock "SingleKES"
    testKESAlgorithm @(Sum1KES Ed25519DSIGN Blake2b_256) lock "Sum1KES"
    testKESAlgorithm @(Sum2KES Ed25519DSIGN Blake2b_256) lock "Sum2KES"
    testKESAlgorithm @(Sum5KES Ed25519DSIGN Blake2b_256) lock "Sum5KES"
    testKESAlgorithm @(CompactSum1KES Ed25519DSIGN Blake2b_256) lock "CompactSum1KES"
    testKESAlgorithm @(CompactSum2KES Ed25519DSIGN Blake2b_256) lock "CompactSum2KES"
    testKESAlgorithm @(CompactSum5KES Ed25519DSIGN Blake2b_256) lock "CompactSum5KES"

--------------------------------------------------------------------------------
-- Show and Eq instances
--------------------------------------------------------------------------------

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

deriving newtype instance EqST (SignKeyDSIGNM d) => EqST (SignKeyKES (SingleKES d))

instance
  ( EqST (SignKeyKES d)
  , Eq (VerKeyKES d)
  , KnownNat (SeedSizeKES d)
  ) =>
  EqST (SignKeyKES (SumKES h d))
  where
  equalsM (SignKeySumKES s r v1 v2) (SignKeySumKES s' r' v1' v2') =
    (s, r, PureEqST v1, PureEqST v2) ==! (s', r', PureEqST v1', PureEqST v2')

deriving newtype instance EqST (SignKeyDSIGNM d) => EqST (SignKeyKES (CompactSingleKES d))

instance
  ( EqST (SignKeyKES d)
  , Eq (VerKeyKES d)
  , KnownNat (SeedSizeKES d)
  ) =>
  EqST (SignKeyKES (CompactSumKES h d))
  where
  equalsM (SignKeyCompactSumKES s r v1 v2) (SignKeyCompactSumKES s' r' v1' v2') =
    (s, r, PureEqST v1, PureEqST v2) ==! (s', r', PureEqST v1', PureEqST v2')

--------------------------------------------------------------------------------
-- Arbitrary instances
--------------------------------------------------------------------------------

genInitialSignKeyKES :: forall k. UnsoundPureKESAlgorithm k => Gen (UnsoundPureSignKeyKES k)
genInitialSignKeyKES = do
  bytes <- BS.pack <$> vector (fromIntegral @Word @Int $ seedSizeKES (Proxy @k))
  let seed = mkSeedFromBytes bytes
  return $ unsoundPureGenKeyKES seed

instance (UnsoundPureKESAlgorithm k, Arbitrary (ContextKES k)) => Arbitrary (UnsoundPureSignKeyKES k) where
  arbitrary = do
    ctx <- arbitrary
    let updateTo :: Period -> Period -> UnsoundPureSignKeyKES k -> Maybe (UnsoundPureSignKeyKES k)
        updateTo target current sk
          | target == current =
              Just sk
          | target > current =
              updateTo target (succ current) =<< unsoundPureUpdateKES ctx sk current
          | otherwise =
              Nothing
    period <- chooseBoundedIntegral (0, totalPeriodsKES (Proxy @k) - 1)
    sk0 <- genInitialSignKeyKES
    let skMay = updateTo period 0 sk0
    case skMay of
      Just sk -> return sk
      Nothing -> error "Attempted to generate SignKeyKES evolved beyond max period"

instance (UnsoundPureKESAlgorithm k, Arbitrary (ContextKES k)) => Arbitrary (VerKeyKES k) where
  arbitrary = unsoundPureDeriveVerKeyKES <$> arbitrary

instance (UnsoundPureKESAlgorithm k, Signable k ByteString, Arbitrary (ContextKES k)) => Arbitrary (SigKES k) where
  arbitrary = do
    sk <- arbitrary
    signable <- BS.pack <$> listOf arbitrary
    ctx <- arbitrary
    return $ unsoundPureSignKES ctx 0 signable sk

--------------------------------------------------------------------------------
-- Tests
--------------------------------------------------------------------------------

testKESAlloc ::
  forall v.
  KESAlgorithm v =>
  Proxy v ->
  String ->
  Spec
testKESAlloc _p n =
  describe n $ do
    describe "Low-level mlocked allocations" $ do
      -- it "updateKey" $ testMLockUpdateKeyKES _p
      it "genKey" $ testMLockGenKeyKES _p

eventTracer :: IORef [event] -> Tracer IO event
eventTracer logVar = Tracer (\ev -> liftIO $ atomicModifyIORef' logVar (\acc -> (acc ++ [ev], ())))

matchAllocLog :: [AllocEvent] -> Set WordPtr
matchAllocLog = F.foldl' (flip go) Set.empty
  where
    go (AllocEv ptr) = Set.insert ptr
    go (FreeEv ptr) = Set.delete ptr
    go (MarkerEv _) = id

testMLockGenKeyKES ::
  forall v.
  KESAlgorithm v =>
  Proxy v ->
  Expectation
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
  [() | AllocEv _ <- after] `shouldSatisfy` (not . null) -- some allocations happened
  evset `shouldSatisfy` null -- all allocations deallocated

{-# NOINLINE testKESAlgorithm #-}
testKESAlgorithm ::
  forall v.
  ( ToCBOR (VerKeyKES v)
  , FromCBOR (VerKeyKES v)
  , EqST (SignKeyKES v) -- only monadic EqST for signing keys
  , Show (SignKeyKES v) -- fake instance defined locally
  , Eq (UnsoundPureSignKeyKES v)
  , Show (UnsoundPureSignKeyKES v)
  , ToCBOR (SigKES v)
  , FromCBOR (SigKES v)
  , Signable v ~ SignableRepresentation
  , ContextKES v ~ ()
  , UnsoundKESAlgorithm v
  , UnsoundPureKESAlgorithm v
  , DirectSerialise (SignKeyKES v)
  , DirectSerialise (VerKeyKES v)
  , DirectDeserialise (SignKeyKES v)
  , DirectDeserialise (VerKeyKES v)
  ) =>
  Lock ->
  String ->
  Spec
testKESAlgorithm lock n =
  describe n $ do
    prop "only gen signkey" $ prop_onlyGenSignKeyKES @v lock
    prop "only gen verkey" $ prop_onlyGenVerKeyKES @v lock
    prop "one update signkey" $ prop_oneUpdateSignKeyKES @v lock
    prop "all updates signkey" $ prop_allUpdatesSignKeyKES @v lock
    prop "total periods" $ prop_totalPeriodsKES @v lock
    describe "NoThunks" $ do
      prop "VerKey" $
        ioPropertyWithSK @v lock $ \sk ->
          prop_no_thunks_IO (deriveVerKeyKES sk)
      prop "SignKey" $
        ioPropertyWithSK @v lock $
          prop_no_thunks_IO . return
      prop "SignKey evolved" $
        ioPropertyWithSK @v lock $ \sk ->
          bracket
            (updateKES () sk 0)
            (maybe (return ()) forgetSignKeyKES)
            (prop_no_thunks_IO . return)
      prop "Sig" $ \seedPSB (msg :: Message) ->
        ioProperty $ withLock lock $ fmap conjoin $ withAllUpdatesKES @v seedPSB $ \t sk -> do
          prop_no_thunks_IO (signKES () t msg sk)
      prop "VerKey DirectSerialise" $
        ioPropertyWithSK @v lock $ \sk -> do
          vk :: VerKeyKES v <- deriveVerKeyKES sk
          direct <- directSerialiseToBS (fromIntegral @Word @Int $ sizeVerKeyKES (Proxy @v)) vk
          prop_no_thunks_IO (return $! direct)
      prop "SignKey DirectSerialise" $
        ioPropertyWithSK @v lock $ \sk -> do
          direct <- directSerialiseToBS (fromIntegral @Word @Int $ sizeSignKeyKES (Proxy @v)) sk
          prop_no_thunks_IO (return $! direct)
      prop "VerKey DirectDeserialise" $
        ioPropertyWithSK @v lock $ \sk -> do
          vk :: VerKeyKES v <- deriveVerKeyKES sk
          direct <- directSerialiseToBS (fromIntegral @Word @Int $ sizeVerKeyKES (Proxy @v)) $! vk
          prop_no_thunks_IO (directDeserialiseFromBS @IO @(VerKeyKES v) $! direct)
      prop "SignKey DirectDeserialise" $
        ioPropertyWithSK @v lock $ \sk -> do
          direct <- directSerialiseToBS (fromIntegral @Word @Int $ sizeSignKeyKES (Proxy @v)) sk
          bracket
            (directDeserialiseFromBS @IO @(SignKeyKES v) $! direct)
            forgetSignKeyKES
            (prop_no_thunks_IO . return)
    prop "same VerKey " $ prop_deriveVerKeyKES @v
    prop "no forgotten chunks in signkey" $ prop_noErasedBlocksInKey (Proxy @v)
    describe "serialisation" $ do
      describe "raw ser only" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            return $ (rawDeserialiseVerKeyKES . rawSerialiseVerKeyKES $ vk) === Just vk
        prop "SignKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            serialized <- rawSerialiseSignKeyKES sk
            equals <-
              bracket
                (rawDeserialiseSignKeyKES serialized)
                (maybe (return ()) forgetSignKeyKES)
                (\msk' -> Just sk ==! msk')
            return $
              counterexample (show serialized) equals
        prop "Sig" $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ \sk -> do
            sig :: SigKES v <- signKES () 0 msg sk
            return $ (rawDeserialiseSigKES . rawSerialiseSigKES $ sig) === Just sig
      describe "size" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            return $
              (fromIntegral @Int @Word . BS.length . rawSerialiseVerKeyKES $ vk) === sizeVerKeyKES (Proxy @v)
        prop "SignKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            serialized <- rawSerialiseSignKeyKES sk
            evaluate ((fromIntegral @Int @Word . BS.length $ serialized) == sizeSignKeyKES (Proxy @v))
        prop "Sig" $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ \sk -> do
            sig :: SigKES v <- signKES () 0 msg sk
            return $ (fromIntegral @Int @Word . BS.length . rawSerialiseSigKES $ sig) === sizeSigKES (Proxy @v)
      describe "direct CBOR" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            return $ prop_cbor_with encodeVerKeyKES decodeVerKeyKES vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        prop "Sig" $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ \sk -> do
            sig :: SigKES v <- signKES () 0 msg sk
            return $ prop_cbor_with encodeSigKES decodeSigKES sig
        prop "UnsoundSignKeyKES" $ \seedPSB ->
          let sk :: UnsoundPureSignKeyKES v = mkUnsoundPureSignKeyKES seedPSB
           in prop_cbor_with encodeUnsoundPureSignKeyKES decodeUnsoundPureSignKeyKES sk
      describe "To/FromCBOR class" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            return $ prop_cbor vk
        -- No To/FromCBOR for 'SignKeyKES', see above.
        prop "Sig" $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ \sk -> do
            sig :: SigKES v <- signKES () 0 msg sk
            return $ prop_cbor sig
      describe "ToCBOR size" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            return $ prop_cbor_size vk
        -- No To/FromCBOR for 'SignKeyKES', see above.
        prop "Sig" $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ \sk -> do
            sig :: SigKES v <- signKES () 0 msg sk
            return $ prop_cbor_size sig
      describe "direct matches class" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            return $ prop_cbor_direct_vs_class encodeVerKeyKES vk
        -- No CBOR testing for SignKey: sign keys are stored in MLocked memory
        -- and require IO for access.
        prop "Sig" $ \(msg :: Message) ->
          ioPropertyWithSK @v lock $ \sk -> do
            sig :: SigKES v <- signKES () 0 msg sk
            return $ prop_cbor_direct_vs_class encodeSigKES sig
      describe "DirectSerialise" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            serialized <- directSerialiseToBS (fromIntegral @Word @Int $ sizeVerKeyKES (Proxy @v)) vk
            vk' <- directDeserialiseFromBS serialized
            return $ vk === vk'
        prop "SignKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            serialized <- directSerialiseToBS (fromIntegral @Word @Int $ sizeSignKeyKES (Proxy @v)) sk
            equals <-
              bracket
                (directDeserialiseFromBS serialized)
                forgetSignKeyKES
                (sk ==!)
            return
              $ counterexample
                ("Serialized: " ++ hexBS serialized ++ " (length: " ++ show (BS.length serialized) ++ ")")
              $ equals
      describe "DirectSerialise matches raw" $ do
        prop "VerKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            vk :: VerKeyKES v <- deriveVerKeyKES sk
            direct <- directSerialiseToBS (fromIntegral @Word @Int $ sizeVerKeyKES (Proxy @v)) vk
            let raw = rawSerialiseVerKeyKES vk
            return $ direct === raw
        prop "SignKey" $
          ioPropertyWithSK @v lock $ \sk -> do
            direct <- directSerialiseToBS (fromIntegral @Word @Int $ sizeSignKeyKES (Proxy @v)) sk
            raw <- rawSerialiseSignKeyKES sk
            return $ direct === raw
    describe "verify" $ do
      prop "positive" $ prop_verifyKES_positive @v
      prop "negative (key)" $ prop_verifyKES_negative_key @v
      prop "negative (message)" $ prop_verifyKES_negative_message @v
      modifyMaxSuccess (min 50) $
        prop "negative (period)" $
          prop_verifyKES_negative_period @v
    describe "serialisation of all KES evolutions" $ do
      prop "VerKey" $ prop_serialise_VerKeyKES @v
      prop "Sig" $ prop_serialise_SigKES @v
    -- TODO: this doesn't pass right now, see
    -- 'prop_key_overwritten_after_forget' for details.
    --
    --  describe "forgetting" $ do
    --    prop "key overwritten after forget" $ prop_key_overwritten_after_forget (Proxy @v)

    describe "unsound pure" $ do
      prop "genKey" $ prop_unsoundPureGenKey @v Proxy
      prop "updateKES" $ prop_unsoundPureUpdateKES @v Proxy
      prop "deriveVerKey" $ prop_unsoundPureDeriveVerKey @v Proxy
      prop "sign" $ prop_unsoundPureSign @v Proxy

-- | Wrap an IO action that requires a 'SignKeyKES' into one that takes an
-- mlocked seed to generate the key from. The key is bracketed off to ensure
-- timely forgetting. Special care must be taken to not leak the key outside of
-- the wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
withSK ::
  KESAlgorithm v =>
  PinnedSizedBytes (SeedSizeKES v) ->
  (SignKeyKES v -> IO b) ->
  IO b
withSK seedPSB =
  bracket
    (withMLockedSeedFromPSB seedPSB genKeyKES)
    forgetSignKeyKES

mkUnsoundPureSignKeyKES ::
  UnsoundPureKESAlgorithm v =>
  PinnedSizedBytes (SeedSizeKES v) ->
  UnsoundPureSignKeyKES v
mkUnsoundPureSignKeyKES psb =
  let seed = mkSeedFromBytes . psbToByteString $ psb
   in unsoundPureGenKeyKES seed

-- | Wrap an IO action that requires a 'SignKeyKES' into a 'Property' that
-- takes a non-mlocked seed (provided as a 'PinnedSizedBytes' of the
-- appropriate size). The key, and the mlocked seed necessary to generate it,
-- are bracketed off, to ensure timely forgetting and avoid leaking mlocked
-- memory. Special care must be taken to not leak the key outside of the
-- wrapped action (be particularly mindful of thunks and unsafe key access
-- here).
ioPropertyWithSK ::
  forall v a.
  (Testable a, KESAlgorithm v) =>
  Lock ->
  (SignKeyKES v -> IO a) ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
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

prop_onlyGenSignKeyKES ::
  forall v.
  KESAlgorithm v =>
  Lock ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_onlyGenSignKeyKES lock =
  ioPropertyWithSK @v lock $ const noExceptionsThrown

prop_onlyGenVerKeyKES ::
  forall v.
  KESAlgorithm v =>
  Lock ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_onlyGenVerKeyKES lock =
  ioPropertyWithSK @v lock $ doesNotThrow . deriveVerKeyKES

prop_oneUpdateSignKeyKES ::
  forall v.
  ( ContextKES v ~ ()
  , KESAlgorithm v
  ) =>
  Lock ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_oneUpdateSignKeyKES lock seedPSB =
  ioProperty . withLock lock . withMLockedSeedFromPSB seedPSB $ \seed -> do
    sk <- genKeyKES @v seed
    msk' <- updateKES () sk 0
    forgetSignKeyKES sk
    maybe (return ()) forgetSignKeyKES msk'
    return True

prop_allUpdatesSignKeyKES ::
  forall v.
  ( ContextKES v ~ ()
  , KESAlgorithm v
  ) =>
  Lock ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_allUpdatesSignKeyKES lock seedPSB =
  ioProperty . withLock lock $ do
    void $ withAllUpdatesKES_ @v seedPSB $ const (return ())

-- | If we start with a signing key, we can evolve it a number of times so that
-- the total number of signing keys (including the initial one) equals the
-- total number of periods for this algorithm.
prop_totalPeriodsKES ::
  forall v.
  ( ContextKES v ~ ()
  , KESAlgorithm v
  ) =>
  Lock ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
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
    totalPeriods = fromIntegral @Word @Int (totalPeriodsKES (Proxy :: Proxy v))

-- | If we start with a signing key, and all its evolutions, the verification
-- keys we derive from each one are the same.
prop_deriveVerKeyKES ::
  forall v.
  ( ContextKES v ~ ()
  , KESAlgorithm v
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
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
prop_verifyKES_positive ::
  forall v.
  ( ContextKES v ~ ()
  , Signable v ~ SignableRepresentation
  , KESAlgorithm v
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  Gen Property
prop_verifyKES_positive seedPSB = do
  xs :: [Message] <- vectorOf totalPeriods arbitrary
  return $
    checkCoverage $
      cover 1 (length xs >= totalPeriods) "Message count covers total periods" $
        not (null xs) ==>
          ioProperty $
            fmap conjoin $ do
              sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @v
              vk <- deriveVerKeyKES sk_0
              forgetSignKeyKES sk_0
              withAllUpdatesKES seedPSB $ \t sk -> do
                let x = cycle xs !! fromIntegral @Word @Int t
                sig <- signKES () t x sk
                let verResult = verifyKES () vk t x sig
                return $
                  counterexample ("period " ++ show t ++ "/" ++ show totalPeriods) $
                    verResult === Right ()
  where
    totalPeriods :: Int
    totalPeriods = fromIntegral @Word @Int (totalPeriodsKES (Proxy :: Proxy v))

-- | If we sign a message @a@with one list of signing key evolutions, if we
-- try to verify the signature (and message @a@) using a verification key
-- corresponding to a different signing key, then the verification fails.
prop_verifyKES_negative_key ::
  forall v.
  ( ContextKES v ~ ()
  , Signable v ~ SignableRepresentation
  , KESAlgorithm v
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Message ->
  Property
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
prop_verifyKES_negative_message ::
  forall v.
  ( ContextKES v ~ ()
  , Signable v ~ SignableRepresentation
  , KESAlgorithm v
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  Message ->
  Message ->
  Property
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
prop_verifyKES_negative_period ::
  forall v.
  ( ContextKES v ~ ()
  , Signable v ~ SignableRepresentation
  , KESAlgorithm v
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  Message ->
  Property
prop_verifyKES_negative_period seedPSB x =
  ioProperty $ fmap conjoin $ do
    sk_0 <- withMLockedSeedFromPSB seedPSB $ genKeyKES @v
    vk <- deriveVerKeyKES sk_0
    forgetSignKeyKES sk_0
    withAllUpdatesKES seedPSB $ \t sk -> do
      sig <- signKES () t x sk
      return $
        conjoin
          [ counterexample ("periods " ++ show (t, t')) $
              verifyKES () vk t' x sig =/= Right ()
          | t' <- [0 .. totalPeriods - 1]
          , t /= t'
          ]
  where
    totalPeriods :: Word
    totalPeriods = totalPeriodsKES (Proxy :: Proxy v)

-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'VerKeyKES' on /all/ the KES key evolutions.
prop_serialise_VerKeyKES ::
  forall v.
  ( ContextKES v ~ ()
  , KESAlgorithm v
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_serialise_VerKeyKES seedPSB =
  ioProperty $ fmap conjoin $ do
    withAllUpdatesKES @v seedPSB $ \t sk -> do
      vk <- deriveVerKeyKES sk
      return $
        counterexample ("period " ++ show t) $
          counterexample ("vkey " ++ show vk) $
            prop_raw_serialise
              rawSerialiseVerKeyKES
              rawDeserialiseVerKeyKES
              vk
              .&. prop_cbor_with
                encodeVerKeyKES
                decodeVerKeyKES
                vk
              .&. prop_size_serialise
                rawSerialiseVerKeyKES
                (sizeVerKeyKES (Proxy @v))
                vk

-- | Check 'prop_raw_serialise', 'prop_cbor_with' and 'prop_size_serialise'
-- for 'SigKES' on /all/ the KES key evolutions.
prop_serialise_SigKES ::
  forall v.
  ( ContextKES v ~ ()
  , Signable v ~ SignableRepresentation
  , Show (SignKeyKES v)
  , KESAlgorithm v
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  Message ->
  Property
prop_serialise_SigKES seedPSB x =
  ioProperty $ fmap conjoin $ do
    withAllUpdatesKES @v seedPSB $ \t sk -> do
      sig <- signKES () t x sk
      return $
        counterexample ("period " ++ show t) $
          counterexample ("vkey " ++ show sk) $
            counterexample ("sig " ++ show sig) $
              prop_raw_serialise
                rawSerialiseSigKES
                rawDeserialiseSigKES
                sig
                .&. prop_cbor_with
                  encodeSigKES
                  decodeSigKES
                  sig
                .&. prop_size_serialise
                  rawSerialiseSigKES
                  (sizeSigKES (Proxy @v))
                  sig

--
-- KES test utils
--

withAllUpdatesKES_ ::
  forall v a.
  ( KESAlgorithm v
  , ContextKES v ~ ()
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  (SignKeyKES v -> IO a) ->
  IO [a]
withAllUpdatesKES_ seedPSB f = do
  withAllUpdatesKES seedPSB (const f)

withAllUpdatesKES ::
  forall v a.
  ( KESAlgorithm v
  , ContextKES v ~ ()
  ) =>
  PinnedSizedBytes (SeedSizeKES v) ->
  (Word -> SignKeyKES v -> IO a) ->
  IO [a]
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
          return $ x : xs

withNullSeed :: forall m n a. (MonadThrow m, MonadST m, KnownNat n) => (MLockedSeed n -> m a) -> m a
withNullSeed =
  bracket
    (MLockedSeed <$> mlsbFromByteString (BS.replicate (fromIntegral @Nat @Int $ natVal (Proxy @n)) 0))
    mlockedSeedFinalize

withNullSK ::
  forall m v a.
  (KESAlgorithm v, MonadThrow m, MonadST m) =>
  (SignKeyKES v -> m a) ->
  m a
withNullSK =
  bracket
    (withNullSeed genKeyKES)
    forgetSignKeyKES

-- | This test detects whether a sign key contains references to pool-allocated
-- blocks of memory that have been forgotten by the time the key is complete.
-- We do this based on the fact that the pooled allocator erases memory blocks
-- by overwriting them with series of 0xff bytes; thus we cut the serialized
-- key up into chunks of 16 bytes, and if any of those chunks is entirely
-- filled with 0xff bytes, we assume that we're looking at erased memory.
prop_noErasedBlocksInKey ::
  forall v.
  UnsoundKESAlgorithm v =>
  DirectSerialise (SignKeyKES v) =>
  Proxy v ->
  Property
prop_noErasedBlocksInKey kesAlgorithm =
  ioProperty . withNullSK @IO @v $ \sk -> do
    let size :: Int = fromIntegral @Word @Int $ sizeSignKeyKES kesAlgorithm
    serialized <- directSerialiseToBS size sk
    forgetSignKeyKES sk
    return $ counterexample (hexBS serialized) $ not (hasLongRunOfFF serialized)

hasLongRunOfFF :: ByteString -> Bool
hasLongRunOfFF bs
  | BS.length bs < 16 =
      False
  | otherwise =
      let first16 = BS.take 16 bs
          remainder = BS.drop 16 bs
       in BS.all (== 0xFF) first16 || hasLongRunOfFF remainder

prop_unsoundPureGenKey ::
  forall v.
  ( UnsoundPureKESAlgorithm v
  , EqST (SignKeyKES v)
  ) =>
  Proxy v ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_unsoundPureGenKey _ seedPSB = ioProperty $ do
  let seed = mkSeedFromBytes $ psbToByteString seedPSB
  let skPure = unsoundPureGenKeyKES @v seed
  withSK seedPSB $ \sk -> do
    bracket
      (unsoundPureSignKeyKESToSoundSignKeyKES skPure)
      forgetSignKeyKES
      (equalsM sk)

prop_unsoundPureDeriveVerKey ::
  forall v.
  UnsoundPureKESAlgorithm v =>
  Proxy v ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_unsoundPureDeriveVerKey _ seedPSB = ioProperty $ do
  let seed = mkSeedFromBytes $ psbToByteString seedPSB
  let skPure = unsoundPureGenKeyKES @v seed
      vkPure = unsoundPureDeriveVerKeyKES @v skPure
  vk <- withSK seedPSB deriveVerKeyKES
  return $ vkPure === vk

prop_unsoundPureUpdateKES ::
  forall v.
  ( UnsoundPureKESAlgorithm v
  , ContextKES v ~ ()
  , EqST (SignKeyKES v)
  ) =>
  Proxy v ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Property
prop_unsoundPureUpdateKES _ seedPSB = ioProperty $ do
  let seed = mkSeedFromBytes $ psbToByteString seedPSB
  let skPure = unsoundPureGenKeyKES @v seed
      skPure'Maybe = unsoundPureUpdateKES () skPure 0
  withSK seedPSB $ \sk -> do
    bracket
      (updateKES () sk 0)
      (maybe (return ()) forgetSignKeyKES)
      $ \sk'Maybe -> do
        case skPure'Maybe of
          Nothing ->
            case sk'Maybe of
              Nothing -> return $ property True
              Just _ -> return $ counterexample "pure does not update, but should" $ property False
          Just skPure' ->
            bracket
              (unsoundPureSignKeyKESToSoundSignKeyKES skPure')
              forgetSignKeyKES
              $ \sk'' ->
                case sk'Maybe of
                  Nothing ->
                    return (counterexample "pure updates, but shouldn't" $ property False)
                  Just sk' ->
                    property <$> equalsM sk' sk''

prop_unsoundPureSign ::
  forall v.
  ( UnsoundPureKESAlgorithm v
  , ContextKES v ~ ()
  , Signable v Message
  ) =>
  Proxy v ->
  PinnedSizedBytes (SeedSizeKES v) ->
  Message ->
  Property
prop_unsoundPureSign _ seedPSB msg = ioProperty $ do
  let seed = mkSeedFromBytes $ psbToByteString seedPSB
  let skPure = unsoundPureGenKeyKES @v seed
      sigPure = unsoundPureSignKES () 0 msg skPure
  sig <- withSK seedPSB $ signKES () 0 msg
  return $ sigPure === sig
