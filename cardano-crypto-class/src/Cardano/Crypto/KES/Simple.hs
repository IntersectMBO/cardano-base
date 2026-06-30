{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}
-- Needed for ghc-9.6 to avoid a redunant constraint warning on the
-- `KESSignAlgorithm m (SimpleKES d t)` instance. Removing the constraint leaves another type
-- error which is rather opaque.
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Simple (
  SimpleKES,
  SigKES (..),
  SignKeyKES (SignKeySimpleKES, ThunkySignKeySimpleKES),
  UnsoundPureSignKeyKES (UnsoundPureSignKeySimpleKES, UnsoundPureThunkySignKeySimpleKES),
)
where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  guardFixedSized,
 )
import Control.Monad (unless, (<$!>))
import Control.Monad.Trans.Maybe
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import Data.Vector (Vector, (!?))
import qualified Data.Vector as Vec
import GHC.Generics (Generic)
import GHC.TypeNats (KnownNat, Nat, natVal, type (*))
import NoThunks.Class (NoThunks)

import Cardano.Base.Bytes (splitsAt)
import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN
import qualified Cardano.Crypto.DSIGN.Class as DSIGN
import Cardano.Crypto.DirectSerialise
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Libsodium.MLockedBytes
import Cardano.Crypto.Libsodium.MLockedSeed
import Cardano.Crypto.Seed
import Data.Maybe (fromMaybe)
import Data.Unit.Strict (forceElemsToWHNF)
import GHC.TypeLits (Natural)

data SimpleKES d (t :: Nat)

-- | 'VerKeySimpleKES' uses a boxed 'Vector', which is lazy in its elements.
-- We don't want laziness and the potential space leak, so we use this pattern
-- synonym to force the elements of the vector to WHNF upon construction.
--
-- The alternative is to use an unboxed vector, but that would require an
-- unreasonable 'Unbox' constraint.
pattern VerKeySimpleKES :: Vector (VerKeyDSIGN d) -> VerKeyKES (SimpleKES d t)
pattern VerKeySimpleKES v <- ThunkyVerKeySimpleKES v
  where
    VerKeySimpleKES v = ThunkyVerKeySimpleKES (forceElemsToWHNF v)

{-# COMPLETE VerKeySimpleKES #-}

-- | See 'VerKeySimpleKES'.
pattern SignKeySimpleKES :: Vector (SignKeyDSIGNM d) -> SignKeyKES (SimpleKES d t)
pattern SignKeySimpleKES v <- ThunkySignKeySimpleKES v
  where
    SignKeySimpleKES v = ThunkySignKeySimpleKES (forceElemsToWHNF v)

{-# COMPLETE SignKeySimpleKES #-}

-- | See 'VerKeySimpleKES'.
pattern UnsoundPureSignKeySimpleKES ::
  Vector (SignKeyDSIGN d) -> UnsoundPureSignKeyKES (SimpleKES d t)
pattern UnsoundPureSignKeySimpleKES v <- UnsoundPureThunkySignKeySimpleKES v
  where
    UnsoundPureSignKeySimpleKES v = UnsoundPureThunkySignKeySimpleKES (forceElemsToWHNF v)

{-# COMPLETE UnsoundPureSignKeySimpleKES #-}

instance
  ( DSIGNMAlgorithm d
  , KnownNat t
  , KnownNat (SeedSizeDSIGN d * t)
  , KnownNat (VerKeySizeDSIGN d * t)
  , KnownNat (SignKeySizeDSIGN d * t)
  ) =>
  KESAlgorithm (SimpleKES d t)
  where
  type SeedSizeKES (SimpleKES d t) = SeedSizeDSIGN d * t

  --
  -- Key and signature types
  --

  newtype VerKeyKES (SimpleKES d t)
    = ThunkyVerKeySimpleKES (Vector (VerKeyDSIGN d))
    deriving (Generic)

  newtype SigKES (SimpleKES d t)
    = SigSimpleKES (SigDSIGN d)
    deriving (Generic)

  newtype SignKeyKES (SimpleKES d t)
    = ThunkySignKeySimpleKES (Vector (SignKeyDSIGNM d))
    deriving (Generic)

  --
  -- Metadata and basic key operations
  --

  algorithmNameKES proxy = "simple_" ++ show (totalPeriodsKES proxy)

  type TotalPeriodsKES (SimpleKES d t) = t

  --
  -- Core algorithm operations
  --

  type ContextKES (SimpleKES d t) = ContextDSIGN d
  type Signable (SimpleKES d t) = DSIGN.Signable d

  verifyKES ctxt (VerKeySimpleKES vks) j a (SigSimpleKES sig) =
    case vks !? fromIntegral @Period @Int j of
      Nothing -> Left "KES verification failed: out of range"
      Just vk -> verifyDSIGN ctxt vk a sig

  --
  -- raw serialise/deserialise
  --

  type SignKeySizeKES (SimpleKES d t) = SignKeySizeDSIGN d * t

  deriveVerKeyKES (SignKeySimpleKES sks) =
    VerKeySimpleKES <$!> Vec.mapM deriveVerKeyDSIGNM sks

  signKES ctxt j a (SignKeySimpleKES sks) =
    case sks !? fromIntegral @Period @Int j of
      Nothing -> error ("SimpleKES.signKES: period out of range " ++ show j)
      Just sk -> SigSimpleKES <$!> (signDSIGNM ctxt a $! sk)

  updateKESWith allocator _ (ThunkySignKeySimpleKES sk) t
    | t + 1 < fromIntegral @Natural @Period (natVal (Proxy @t)) = do
        sk' <- Vec.mapM (cloneKeyDSIGNMWith allocator) sk
        return $! Just $! SignKeySimpleKES sk'
    | otherwise = return Nothing

  --
  -- Key generation
  --

  genKeyKESWith allocator (MLockedSeed mlsb) = do
    let seedSize = seedSizeDSIGN (Proxy :: Proxy d)
        duration = fromIntegral @Natural @Int (natVal (Proxy @t))
    sks <- Vec.generateM duration $ \t -> do
      withMLSBChunk mlsb (t * fromIntegral @Word @Int seedSize) $ \mlsb' -> do
        genKeyDSIGNMWith allocator (MLockedSeed mlsb')
    return $! SignKeySimpleKES sks

  --
  -- Forgetting
  --

  forgetSignKeyKESWith allocator (SignKeySimpleKES sks) =
    Vec.mapM_ (forgetSignKeyDSIGNMWith allocator) sks

instance
  ( KESAlgorithm (SimpleKES d t)
  , KnownNat t
  , DSIGNAlgorithm d
  , UnsoundDSIGNMAlgorithm d
  ) =>
  UnsoundPureKESAlgorithm (SimpleKES d t)
  where
  newtype UnsoundPureSignKeyKES (SimpleKES d t)
    = UnsoundPureThunkySignKeySimpleKES (Vector (SignKeyDSIGN d))
    deriving (Generic)

  unsoundPureGenKeyKES seed =
    let seedSize = fromIntegral @Word @Int (seedSizeDSIGN (Proxy :: Proxy d))
        duration = fromIntegral @Natural @Int (natVal (Proxy @t))
        seedChunk t =
          mkSeedFromBytes (BS.take seedSize . BS.drop (seedSize * t) $ getSeedBytes seed)
     in UnsoundPureSignKeySimpleKES $
          Vec.generate duration (genKeyDSIGN . seedChunk)

  unsoundPureSignKES ctxt j a (UnsoundPureSignKeySimpleKES sks) =
    case sks !? fromIntegral @Period @Int j of
      Nothing -> error ("SimpleKES.unsoundPureSignKES: period out of range " ++ show j)
      Just sk -> SigSimpleKES $! signDSIGN ctxt a sk

  unsoundPureUpdateKES _ (UnsoundPureThunkySignKeySimpleKES sk) t
    | t + 1 < fromIntegral @Natural @Period (natVal (Proxy @t)) =
        Just $! UnsoundPureThunkySignKeySimpleKES sk
    | otherwise =
        Nothing

  unsoundPureDeriveVerKeyKES (UnsoundPureSignKeySimpleKES sks) =
    VerKeySimpleKES $! Vec.map deriveVerKeyDSIGN sks

  unsoundPureSignKeyKESToSoundSignKeyKES (UnsoundPureThunkySignKeySimpleKES sks) = do
    SignKeySimpleKES <$> mapM convertSK sks
    where
      convertSK =
        fmap (fromMaybe (error "unsoundPureSignKeyKESToSoundSignKeyKES: deserialisation failed"))
          . rawDeserialiseSignKeyDSIGNM
          . rawSerialiseSignKeyDSIGN

instance
  (UnsoundDSIGNMAlgorithm d, KnownNat t, KESAlgorithm (SimpleKES d t)) =>
  UnsoundKESAlgorithm (SimpleKES d t)
  where
  --
  -- raw serialise/deserialise
  --

  rawSerialiseSignKeyKES (SignKeySimpleKES sks) =
    BS.concat <$!> mapM rawSerialiseSignKeyDSIGNM (Vec.toList sks)

  rawDeserialiseSignKeyKESWith allocator bs
    | let duration = fromIntegral @Natural @Int (natVal (Proxy :: Proxy t))
          sizeKey = fromIntegral @Word @Int (signKeySizeDSIGN (Proxy :: Proxy d))
    , skbs <- splitsAt (replicate duration sizeKey) bs
    , length skbs == duration =
        runMaybeT $ do
          sks <- mapM (MaybeT . rawDeserialiseSignKeyDSIGNMWith allocator) skbs
          return $! SignKeySimpleKES (Vec.fromList sks)
    | otherwise =
        return Nothing

instance
  ( DSIGNAlgorithm d
  , KnownNat t
  , KnownNat (VerKeySizeDSIGN d * t)
  ) =>
  FixedSizeCodec (VerKeyKES (SimpleKES d t))
  where
  type FixedSize (VerKeyKES (SimpleKES d t)) = VerKeySizeDSIGN d * t
  rawEncodeFixedSized (VerKeySimpleKES vks) =
    BS.concat [rawEncodeFixedSized vk | vk <- Vec.toList vks]
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    let duration = fromIntegral @Natural @Int (natVal (Proxy :: Proxy t))
        sizeKey = fromIntegral @Word @Int (verKeySizeDSIGN (Proxy :: Proxy d))
        vkbs = splitsAt (replicate duration sizeKey) bs
    unless (length vkbs == duration) $
      fail "VerKeyKES (SimpleKES d t): vkbs length is not equal to duration"
    vks <- mapM rawDecodeFixedSized vkbs
    return $! VerKeySimpleKES (Vec.fromList vks)
  {-# INLINE rawDecodeFixedSized #-}

instance
  (DSIGNAlgorithm d, KnownNat t) =>
  FixedSizeCodec (SigKES (SimpleKES d t))
  where
  type FixedSize (SigKES (SimpleKES d t)) = SigSizeDSIGN d
  rawEncodeFixedSized (SigSimpleKES sig) = rawEncodeFixedSized sig
  rawDecodeFixedSized bs = SigSimpleKES <$> rawDecodeFixedSized bs
  {-# INLINE rawDecodeFixedSized #-}

instance
  ( DSIGNAlgorithm d
  , KnownNat t
  , KnownNat (SignKeySizeDSIGN d * t)
  ) =>
  FixedSizeCodec (UnsoundPureSignKeyKES (SimpleKES d t))
  where
  type FixedSize (UnsoundPureSignKeyKES (SimpleKES d t)) = SignKeySizeKES (SimpleKES d t)
  rawEncodeFixedSized (UnsoundPureSignKeySimpleKES sks) =
    foldMap rawEncodeFixedSized sks
  rawDecodeFixedSized bs = guardFixedSized bs $ do
    let duration = fromIntegral @Natural @Int (natVal (Proxy :: Proxy t))
        sizeKey = fromIntegral @Word @Int (signKeySizeDSIGN (Proxy :: Proxy d))
        skbs = splitsAt (replicate duration sizeKey) bs
    unless (length skbs == duration) $
      fail "UnsoundPureSignKeyKES (SimpleKES d t): vkbs length is not equal to duration"
    sks <- mapM rawDecodeFixedSized skbs
    return $! UnsoundPureSignKeySimpleKES (Vec.fromList sks)
  {-# INLINE rawDecodeFixedSized #-}

deriving instance DSIGNMAlgorithm d => Show (VerKeyKES (SimpleKES d t))
deriving instance (DSIGNMAlgorithm d, Show (SignKeyDSIGNM d)) => Show (SignKeyKES (SimpleKES d t))
deriving instance
  (DSIGNMAlgorithm d, Show (SignKeyDSIGNM d)) => Show (UnsoundPureSignKeyKES (SimpleKES d t))
deriving instance DSIGNMAlgorithm d => Show (SigKES (SimpleKES d t))

deriving instance DSIGNMAlgorithm d => Eq (VerKeyKES (SimpleKES d t))
deriving instance DSIGNMAlgorithm d => Eq (SigKES (SimpleKES d t))
deriving instance Eq (SignKeyDSIGN d) => Eq (UnsoundPureSignKeyKES (SimpleKES d t))

instance DSIGNMAlgorithm d => NoThunks (SigKES (SimpleKES d t))
instance DSIGNMAlgorithm d => NoThunks (SignKeyKES (SimpleKES d t))
instance DSIGNMAlgorithm d => NoThunks (UnsoundPureSignKeyKES (SimpleKES d t))
instance DSIGNMAlgorithm d => NoThunks (VerKeyKES (SimpleKES d t))

instance
  ( DSIGNMAlgorithm d
  , KnownNat t
  , KnownNat (SeedSizeDSIGN d * t)
  , KnownNat (VerKeySizeDSIGN d * t)
  , KnownNat (SignKeySizeDSIGN d * t)
  ) =>
  ToCBOR (VerKeyKES (SimpleKES d t))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance
  ( DSIGNMAlgorithm d
  , KnownNat t
  , KnownNat (SeedSizeDSIGN d * t)
  , KnownNat (VerKeySizeDSIGN d * t)
  , KnownNat (SignKeySizeDSIGN d * t)
  ) =>
  FromCBOR (VerKeyKES (SimpleKES d t))
  where
  fromCBOR = decodeFixedSized

instance
  ( DSIGNMAlgorithm d
  , KnownNat t
  , KnownNat (SeedSizeDSIGN d * t)
  , KnownNat (VerKeySizeDSIGN d * t)
  , KnownNat (SignKeySizeDSIGN d * t)
  ) =>
  ToCBOR (SigKES (SimpleKES d t))
  where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance
  ( DSIGNMAlgorithm d
  , KnownNat t
  , KnownNat (SeedSizeDSIGN d * t)
  , KnownNat (VerKeySizeDSIGN d * t)
  , KnownNat (SignKeySizeDSIGN d * t)
  ) =>
  FromCBOR (SigKES (SimpleKES d t))
  where
  fromCBOR = decodeFixedSized

instance DirectSerialise (VerKeyDSIGN d) => DirectSerialise (VerKeyKES (SimpleKES d t)) where
  directSerialise push (VerKeySimpleKES vks) =
    mapM_ (directSerialise push) vks

instance (DirectDeserialise (VerKeyDSIGN d), KnownNat t) => DirectDeserialise (VerKeyKES (SimpleKES d t)) where
  directDeserialise pull = do
    let duration = fromIntegral @Natural @Int (natVal (Proxy :: Proxy t))
    vks <- Vec.replicateM duration (directDeserialise pull)
    return $! VerKeySimpleKES vks

instance DirectSerialise (SignKeyDSIGNM d) => DirectSerialise (SignKeyKES (SimpleKES d t)) where
  directSerialise push (SignKeySimpleKES sks) =
    mapM_ (directSerialise push) sks

instance (DirectDeserialise (SignKeyDSIGNM d), KnownNat t) => DirectDeserialise (SignKeyKES (SimpleKES d t)) where
  directDeserialise pull = do
    let duration = fromIntegral @Natural @Int (natVal (Proxy :: Proxy t))
    sks <- Vec.replicateM duration (directDeserialise pull)
    return $! SignKeySimpleKES sks
