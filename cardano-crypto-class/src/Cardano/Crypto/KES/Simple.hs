{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Simple
  ( SimpleKES
  , SigKES (..)
  , SignKeyKES (SignKeySimpleKES, ThunkySignKeySimpleKES)
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
import           Control.Monad.Class.MonadThrow (MonadEvaluate)
import           Control.Monad.Class.MonadST (MonadST)
import           Control.Monad ((<$!>), forM)

import           Cardano.Binary (FromCBOR (..), ToCBOR (..))

import           Cardano.Crypto.DSIGN
import           Cardano.Crypto.KES.Class
import           Cardano.Crypto.MLockedSeed
import           Cardano.Crypto.Libsodium.MLockedBytes
import           Cardano.Crypto.Util
import           Data.Unit.Strict (forceElemsToWHNF)
import           Cardano.Crypto.MonadSodium (MonadSodium (..), MEq (..))


data SimpleKES d (t :: Nat)

-- | 'VerKeySimpleKES' uses a boxed 'Vector', which is lazy in its elements.
-- We don't want laziness and the potential space leak, so we use this pattern
-- synonym to force the elements of the vector to WHNF upon construction.
--
-- The alternative is to use an unboxed vector, but that would require an
-- unreasonable 'Unbox' constraint.
pattern VerKeySimpleKES :: Vector (VerKeyDSIGNM d) -> VerKeyKES (SimpleKES d t)
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

instance ( DSIGNMAlgorithmBase d
         , KnownNat t
         , KnownNat (SeedSizeDSIGNM d * t)
         , KnownNat (SizeVerKeyDSIGNM d * t)
         , KnownNat (SizeSignKeyDSIGNM d * t)
         )
         => KESAlgorithm (SimpleKES d t) where

    type SeedSizeKES (SimpleKES d t) = SeedSizeDSIGNM d * t

    --
    -- Key and signature types
    --

    newtype VerKeyKES (SimpleKES d t) =
              ThunkyVerKeySimpleKES (Vector (VerKeyDSIGNM d))
        deriving Generic

    newtype SigKES (SimpleKES d t) =
              SigSimpleKES (SigDSIGNM d)
        deriving Generic


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES proxy = "simple_" ++ show (totalPeriodsKES proxy)

    totalPeriodsKES  _ = fromIntegral (natVal (Proxy @t))

    --
    -- Core algorithm operations
    --

    type ContextKES (SimpleKES d t) = ContextDSIGNM d
    type Signable   (SimpleKES d t) = SignableM d

    verifyKES ctxt (VerKeySimpleKES vks) j a (SigSimpleKES sig) =
        case vks !? fromIntegral j of
          Nothing -> Left "KES verification failed: out of range"
          Just vk -> verifyDSIGNM ctxt vk a sig

    --
    -- raw serialise/deserialise
    --

    type SizeVerKeyKES  (SimpleKES d t) = SizeVerKeyDSIGNM d * t
    type SizeSignKeyKES (SimpleKES d t) = SizeSignKeyDSIGNM d * t
    type SizeSigKES     (SimpleKES d t) = SizeSigDSIGNM d

    rawSerialiseVerKeyKES (VerKeySimpleKES vks) =
        BS.concat [ rawSerialiseVerKeyDSIGNM vk | vk <- Vec.toList vks ]

    rawSerialiseSigKES (SigSimpleKES sig) =
        rawSerialiseSigDSIGNM sig

    rawDeserialiseVerKeyKES bs
      | let duration = fromIntegral (natVal (Proxy :: Proxy t))
            sizeKey  = fromIntegral (sizeVerKeyDSIGNM (Proxy :: Proxy d))
      , vkbs     <- splitsAt (replicate duration sizeKey) bs
      , length vkbs == duration
      , Just vks <- mapM rawDeserialiseVerKeyDSIGNM vkbs
      = Just $! VerKeySimpleKES (Vec.fromList vks)

      | otherwise
      = Nothing

    rawDeserialiseSigKES = fmap SigSimpleKES . rawDeserialiseSigDSIGNM



instance ( KESAlgorithm (SimpleKES d t)
         , DSIGNMAlgorithm m d
         , KnownNat t
         , KnownNat (SeedSizeDSIGNM d * t)
         , MonadEvaluate m
         , MonadSodium m
         , MonadST m
         ) =>
         KESSignAlgorithm m (SimpleKES d t) where
    newtype SignKeyKES (SimpleKES d t) =
              ThunkySignKeySimpleKES (Vector (SignKeyDSIGNM d))
        deriving Generic


    deriveVerKeyKES (SignKeySimpleKES sks) =
      VerKeySimpleKES <$!> Vec.mapM deriveVerKeyDSIGNM sks


    signKES ctxt j a (SignKeySimpleKES sks) =
        case sks !? fromIntegral j of
          Nothing -> error ("SimpleKES.signKES: period out of range " ++ show j)
          Just sk -> SigSimpleKES <$!> (signDSIGNM ctxt a $! sk)

    updateKES _ (ThunkySignKeySimpleKES sk) t
      | t+1 < fromIntegral (natVal (Proxy @t)) = do
          sk' <- Vec.mapM cloneKeyDSIGNM $! sk
          return $! Just $! SignKeySimpleKES sk'
      | otherwise                               = return $! Nothing


    --
    -- Key generation
    --

    genKeyKES (MLockedSeed mlsb) = do
      let seedSize = seedSizeDSIGNM (Proxy :: Proxy d)
          duration = fromIntegral (natVal (Proxy @t))
      sks <- forM [0 .. (duration - 1)] $ \t -> do
        withMLSBChunk mlsb (fromIntegral $ t * seedSize) $ \mlsb' -> do
          genKeyDSIGNM (MLockedSeed mlsb')
      return $! SignKeySimpleKES $! Vec.fromList $! sks

    --
    -- Forgetting
    --

    forgetSignKeyKES (SignKeySimpleKES sks) = Vec.mapM_ forgetSignKeyDSIGNM sks



instance ( UnsoundDSIGNMAlgorithm m d, KnownNat t, KESSignAlgorithm m (SimpleKES d t))
         => UnsoundKESSignAlgorithm m (SimpleKES d t) where
    --
    -- raw serialise/deserialise
    --

    rawSerialiseSignKeyKES (SignKeySimpleKES sks) =
        BS.concat <$!> mapM rawSerialiseSignKeyDSIGNM (Vec.toList sks)


    rawDeserialiseSignKeyKES bs
      | let duration = fromIntegral (natVal (Proxy :: Proxy t))
            sizeKey  = fromIntegral (sizeSignKeyDSIGNM (Proxy :: Proxy d))
      , skbs     <- splitsAt (replicate duration sizeKey) bs
      , length skbs == duration
      = runMaybeT $ do
          sks <- mapM (MaybeT . rawDeserialiseSignKeyDSIGNM) skbs
          return $! SignKeySimpleKES (Vec.fromList sks)

      | otherwise
      = return Nothing

deriving instance DSIGNMAlgorithmBase d => Show (VerKeyKES (SimpleKES d t))
deriving instance DSIGNMAlgorithmBase d => Show (SignKeyKES (SimpleKES d t))
deriving instance DSIGNMAlgorithmBase d => Show (SigKES (SimpleKES d t))

deriving instance DSIGNMAlgorithmBase d => Eq   (VerKeyKES (SimpleKES d t))
deriving instance DSIGNMAlgorithmBase d => Eq   (SigKES (SimpleKES d t))

instance (Monad m, MEq m (SignKeyDSIGNM d)) => MEq m (SignKeyKES (SimpleKES d t)) where
  equalsM (ThunkySignKeySimpleKES a) (ThunkySignKeySimpleKES b) =
    Vec.all id <$> Vec.zipWithM equalsM a b


instance DSIGNMAlgorithmBase d => NoThunks (SigKES     (SimpleKES d t))
instance DSIGNMAlgorithmBase d => NoThunks (SignKeyKES (SimpleKES d t))
instance DSIGNMAlgorithmBase d => NoThunks (VerKeyKES  (SimpleKES d t))

instance ( DSIGNMAlgorithmBase d
         , KnownNat t
         , KnownNat (SeedSizeDSIGNM d * t)
         , KnownNat (SizeVerKeyDSIGNM d * t)
         , KnownNat (SizeSignKeyDSIGNM d * t)
         )
      => ToCBOR (VerKeyKES (SimpleKES d t)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance ( DSIGNMAlgorithmBase d
         , KnownNat t
         , KnownNat (SeedSizeDSIGNM d * t)
         , KnownNat (SizeVerKeyDSIGNM d * t)
         , KnownNat (SizeSignKeyDSIGNM d * t)
         )
      => FromCBOR (VerKeyKES (SimpleKES d t)) where
  fromCBOR = decodeVerKeyKES

instance ( DSIGNMAlgorithmBase d
         , KnownNat t
         , KnownNat (SeedSizeDSIGNM d * t)
         , KnownNat (SizeVerKeyDSIGNM d * t)
         , KnownNat (SizeSignKeyDSIGNM d * t)
         )
      => ToCBOR (SigKES (SimpleKES d t)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance (DSIGNMAlgorithmBase d
         , KnownNat t
         , KnownNat (SeedSizeDSIGNM d * t)
         , KnownNat (SizeVerKeyDSIGNM d * t)
         , KnownNat (SizeSignKeyDSIGNM d * t)
         )
      => FromCBOR (SigKES (SimpleKES d t)) where
  fromCBOR = decodeSigKES

