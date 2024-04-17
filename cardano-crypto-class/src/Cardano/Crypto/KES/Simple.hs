{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- Needed for ghc-9.6 to avoid a redunant constraint warning on the
-- `KESSignAlgorithm m (SimpleKES d t)` instance. Removing the constraint leaves another type
-- error which is rather opaque.
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Simple
  ( SimpleKES
  , SigKES (..)
  , SignKeyKES (SignKeySimpleKES, ThunkySignKeySimpleKES)
  , UnsoundPureSignKeyKES (UnsoundPureSignKeySimpleKES, UnsoundPureThunkySignKeySimpleKES)
  )
where

import           Data.Proxy (Proxy (..))
import qualified Data.ByteString as BS
import           Data.Vector ((!?), Vector)
import qualified Data.Vector as Vec
import           GHC.Generics (Generic)
import           GHC.TypeNats (Nat, KnownNat, natVal, type (*))
import           NoThunks.Class (NoThunks)
import           Control.Monad.Trans.Maybe
import           Control.Monad ( (<$!>) )

import           Cardano.Binary (FromCBOR (..), ToCBOR (..))

import           Cardano.Crypto.DSIGN
import qualified Cardano.Crypto.DSIGN.Class as DSIGN
import           Cardano.Crypto.KES.Class
import           Cardano.Crypto.Libsodium.MLockedSeed
import           Cardano.Crypto.Libsodium.MLockedBytes
import           Cardano.Crypto.Util
import           Cardano.Crypto.Seed
import           Cardano.Crypto.DirectSerialise
import           Data.Unit.Strict (forceElemsToWHNF)
import           Data.Maybe (fromMaybe)

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
pattern UnsoundPureSignKeySimpleKES :: Vector (SignKeyDSIGN d) -> UnsoundPureSignKeyKES (SimpleKES d t)
pattern UnsoundPureSignKeySimpleKES v <- UnsoundPureThunkySignKeySimpleKES v
  where
    UnsoundPureSignKeySimpleKES v = UnsoundPureThunkySignKeySimpleKES (forceElemsToWHNF v)

{-# COMPLETE UnsoundPureSignKeySimpleKES #-}

instance ( DSIGNMAlgorithm d
         , KnownNat t
         , KnownNat (SeedSizeDSIGN d * t)
         , KnownNat (SizeVerKeyDSIGN d * t)
         , KnownNat (SizeSignKeyDSIGN d * t)
         )
         => KESAlgorithm (SimpleKES d t) where

    type SeedSizeKES (SimpleKES d t) = SeedSizeDSIGN d * t

    --
    -- Key and signature types
    --

    newtype VerKeyKES (SimpleKES d t) =
              ThunkyVerKeySimpleKES (Vector (VerKeyDSIGN d))
        deriving Generic

    newtype SigKES (SimpleKES d t) =
              SigSimpleKES (SigDSIGN d)
        deriving Generic

    newtype SignKeyKES (SimpleKES d t) =
              ThunkySignKeySimpleKES (Vector (SignKeyDSIGNM d))
        deriving Generic

    --
    -- Metadata and basic key operations
    --

    algorithmNameKES proxy = "simple_" ++ show (totalPeriodsKES proxy)

    totalPeriodsKES  _ = fromIntegral (natVal (Proxy @t))

    --
    -- Core algorithm operations
    --

    type ContextKES (SimpleKES d t) = ContextDSIGN d
    type Signable   (SimpleKES d t) = DSIGN.Signable d

    verifyKES ctxt (VerKeySimpleKES vks) j a (SigSimpleKES sig) =
        case vks !? fromIntegral j of
          Nothing -> Left "KES verification failed: out of range"
          Just vk -> verifyDSIGN ctxt vk a sig

    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES  (SimpleKES d t) = SizeVerKeyDSIGN d * t
    type SizeSignKeyKES (SimpleKES d t) = SizeSignKeyDSIGN d * t
    type SizeSigKES     (SimpleKES d t) = SizeSigDSIGN d

    rawSerialiseVerKeyKES (VerKeySimpleKES vks) =
        BS.concat [ rawSerialiseVerKeyDSIGN vk | vk <- Vec.toList vks ]

    rawSerialiseSigKES (SigSimpleKES sig) =
        rawSerialiseSigDSIGN sig

    rawDeserialiseVerKeyKES bs
      | let duration = fromIntegral (natVal (Proxy :: Proxy t))
            sizeKey  = fromIntegral (sizeVerKeyDSIGN (Proxy :: Proxy d))
      , vkbs     <- splitsAt (replicate duration sizeKey) bs
      , length vkbs == duration
      , Just vks <- mapM rawDeserialiseVerKeyDSIGN vkbs
      = Just $! VerKeySimpleKES (Vec.fromList vks)

      | otherwise
      = Nothing

    rawDeserialiseSigKES = fmap SigSimpleKES . rawDeserialiseSigDSIGN

    deriveVerKeyKES (SignKeySimpleKES sks) =
      VerKeySimpleKES <$!> Vec.mapM deriveVerKeyDSIGNM sks


    signKES ctxt j a (SignKeySimpleKES sks) =
        case sks !? fromIntegral j of
          Nothing -> error ("SimpleKES.signKES: period out of range " ++ show j)
          Just sk -> SigSimpleKES <$!> (signDSIGNM ctxt a $! sk)

    updateKESWith allocator _ (ThunkySignKeySimpleKES sk) t
      | t+1 < fromIntegral (natVal (Proxy @t)) = do
          sk' <- Vec.mapM (cloneKeyDSIGNMWith allocator) sk
          return $! Just $! SignKeySimpleKES sk'
      | otherwise                               = return Nothing


    --
    -- Key generation
    --

    genKeyKESWith allocator (MLockedSeed mlsb) = do
      let seedSize = seedSizeDSIGN (Proxy :: Proxy d)
          duration = fromIntegral (natVal (Proxy @t))
      sks <- Vec.generateM duration $ \t -> do
        withMLSBChunk mlsb (fromIntegral t * fromIntegral seedSize) $ \mlsb' -> do
          genKeyDSIGNMWith allocator (MLockedSeed mlsb')
      return $! SignKeySimpleKES sks

    --
    -- Forgetting
    --

    forgetSignKeyKESWith allocator (SignKeySimpleKES sks) =
      Vec.mapM_ (forgetSignKeyDSIGNMWith allocator) sks

instance ( KESAlgorithm (SimpleKES d t)
         , KnownNat t
         , DSIGNAlgorithm d
         , UnsoundDSIGNMAlgorithm d
         )
         => UnsoundPureKESAlgorithm (SimpleKES d t) where

    newtype UnsoundPureSignKeyKES (SimpleKES d t) =
              UnsoundPureThunkySignKeySimpleKES (Vector (SignKeyDSIGN d))
        deriving Generic

    unsoundPureGenKeyKES seed =
      let seedSize = fromIntegral (seedSizeDSIGN (Proxy :: Proxy d))
          duration = fromIntegral (natVal (Proxy @t))
          seedChunk t =
            mkSeedFromBytes (BS.take seedSize . BS.drop (seedSize * t) $ getSeedBytes seed)
      in
        UnsoundPureSignKeySimpleKES $
          Vec.generate duration (\t ->
            genKeyDSIGN (seedChunk t))

    unsoundPureSignKES ctxt j a (UnsoundPureSignKeySimpleKES sks) =
        case sks !? fromIntegral j of
          Nothing -> error ("SimpleKES.unsoundPureSignKES: period out of range " ++ show j)
          Just sk -> SigSimpleKES $! (signDSIGN ctxt a $! sk)

    unsoundPureUpdateKES _ (UnsoundPureThunkySignKeySimpleKES sk) t
      | t+1 < fromIntegral (natVal (Proxy @t))
      = Just $! UnsoundPureThunkySignKeySimpleKES sk
      | otherwise
      = Nothing

    unsoundPureDeriveVerKeyKES (UnsoundPureSignKeySimpleKES sks) =
      VerKeySimpleKES $! Vec.map deriveVerKeyDSIGN sks

    unsoundPureSignKeyKESToSoundSignKeyKES (UnsoundPureThunkySignKeySimpleKES sks) = do
      SignKeySimpleKES <$> mapM convertSK sks
      where
        convertSK = fmap (fromMaybe (error "unsoundPureSignKeyKESToSoundSignKeyKES: deserialisation failed"))
                      . rawDeserialiseSignKeyDSIGNM
                      . rawSerialiseSignKeyDSIGN
          
    rawSerialiseUnsoundPureSignKeyKES (UnsoundPureSignKeySimpleKES sks) =
        BS.concat $! map rawSerialiseSignKeyDSIGN (Vec.toList sks)


    rawDeserialiseUnsoundPureSignKeyKES bs
      | let duration = fromIntegral (natVal (Proxy :: Proxy t))
            sizeKey  = fromIntegral (sizeSignKeyDSIGN (Proxy :: Proxy d))
            skbs     = splitsAt (replicate duration sizeKey) bs
      , length skbs == duration
      = do
          sks <- mapM rawDeserialiseSignKeyDSIGN skbs
          return $! UnsoundPureSignKeySimpleKES (Vec.fromList sks)

      | otherwise
      = Nothing



instance ( UnsoundDSIGNMAlgorithm d, KnownNat t, KESAlgorithm (SimpleKES d t))
         => UnsoundKESAlgorithm (SimpleKES d t) where
    --
    -- raw serialise/deserialise
    --

    rawSerialiseSignKeyKES (SignKeySimpleKES sks) =
        BS.concat <$!> mapM rawSerialiseSignKeyDSIGNM (Vec.toList sks)


    rawDeserialiseSignKeyKESWith allocator bs
      | let duration = fromIntegral (natVal (Proxy :: Proxy t))
            sizeKey  = fromIntegral (sizeSignKeyDSIGN (Proxy :: Proxy d))
      , skbs     <- splitsAt (replicate duration sizeKey) bs
      , length skbs == duration
      = runMaybeT $ do
          sks <- mapM (MaybeT . rawDeserialiseSignKeyDSIGNMWith allocator) skbs
          return $! SignKeySimpleKES (Vec.fromList sks)

      | otherwise
      = return Nothing

deriving instance DSIGNMAlgorithm d => Show (VerKeyKES (SimpleKES d t))
deriving instance (DSIGNMAlgorithm d, Show (SignKeyDSIGNM d)) => Show (SignKeyKES (SimpleKES d t))
deriving instance DSIGNMAlgorithm d => Show (SigKES (SimpleKES d t))

deriving instance DSIGNMAlgorithm d => Eq   (VerKeyKES (SimpleKES d t))
deriving instance DSIGNMAlgorithm d => Eq   (SigKES (SimpleKES d t))

instance DSIGNMAlgorithm d => NoThunks (SigKES     (SimpleKES d t))
instance DSIGNMAlgorithm d => NoThunks (SignKeyKES (SimpleKES d t))
instance DSIGNMAlgorithm d => NoThunks (VerKeyKES  (SimpleKES d t))

instance ( DSIGNMAlgorithm d
         , KnownNat t
         , KnownNat (SeedSizeDSIGN d * t)
         , KnownNat (SizeVerKeyDSIGN d * t)
         , KnownNat (SizeSignKeyDSIGN d * t)
         )
      => ToCBOR (VerKeyKES (SimpleKES d t)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance ( DSIGNMAlgorithm d
         , KnownNat t
         , KnownNat (SeedSizeDSIGN d * t)
         , KnownNat (SizeVerKeyDSIGN d * t)
         , KnownNat (SizeSignKeyDSIGN d * t)
         )
      => FromCBOR (VerKeyKES (SimpleKES d t)) where
  fromCBOR = decodeVerKeyKES

instance ( DSIGNMAlgorithm d
         , KnownNat t
         , KnownNat (SeedSizeDSIGN d * t)
         , KnownNat (SizeVerKeyDSIGN d * t)
         , KnownNat (SizeSignKeyDSIGN d * t)
         )
      => ToCBOR (SigKES (SimpleKES d t)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance (DSIGNMAlgorithm d
         , KnownNat t
         , KnownNat (SeedSizeDSIGN d * t)
         , KnownNat (SizeVerKeyDSIGN d * t)
         , KnownNat (SizeSignKeyDSIGN d * t)
         )
      => FromCBOR (SigKES (SimpleKES d t)) where
  fromCBOR = decodeSigKES

instance (DirectSerialise (VerKeyDSIGN d)) => DirectSerialise (VerKeyKES (SimpleKES d t)) where
  directSerialise push (VerKeySimpleKES vks) =
    mapM_ (directSerialise push) vks

instance (DirectDeserialise (VerKeyDSIGN d), KnownNat t) => DirectDeserialise (VerKeyKES (SimpleKES d t)) where
  directDeserialise pull = do
    let duration = fromIntegral (natVal (Proxy :: Proxy t))
    vks <- Vec.replicateM duration (directDeserialise pull)
    return $! VerKeySimpleKES $! vks

instance (DirectSerialise (SignKeyDSIGNM d)) => DirectSerialise (SignKeyKES (SimpleKES d t)) where
  directSerialise push (SignKeySimpleKES sks) =
    mapM_ (directSerialise push) sks

instance (DirectDeserialise (SignKeyDSIGNM d), KnownNat t) => DirectDeserialise (SignKeyKES (SimpleKES d t)) where
  directDeserialise pull = do
    let duration = fromIntegral (natVal (Proxy :: Proxy t))
    sks <- Vec.replicateM duration (directDeserialise pull)
    return $! SignKeySimpleKES $! sks
