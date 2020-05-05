{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Simple
  ( SimpleKES
  , SigKES (..)
  , SignKeyKES (..)
  )
where

import           Data.List (unfoldr)
import           Data.Proxy (Proxy (..))
import           Data.Typeable (Typeable)
import           Data.Vector ((!?), Vector)
import qualified Data.Vector as Vec
import           GHC.Generics (Generic)
import           GHC.TypeNats (Nat, KnownNat, natVal)

import           Control.Monad (replicateM)

import           Cardano.Prelude (NoUnexpectedThunks)
import           Cardano.Binary
                   (FromCBOR (..), ToCBOR (..), decodeListLen, encodeListLen)

import           Cardano.Crypto.DSIGN
import qualified Cardano.Crypto.DSIGN as DSIGN
import           Cardano.Crypto.KES.Class
import           Cardano.Crypto.Seed


data SimpleKES d (t :: Nat)

instance (DSIGNAlgorithm d, Typeable d, KnownNat t) =>
         KESAlgorithm (SimpleKES d t) where


    --
    -- Key and signature types
    --

    newtype VerKeyKES (SimpleKES d t) =
              VerKeySimpleKES (Vector (VerKeyDSIGN d))
        deriving Generic

    newtype SignKeyKES (SimpleKES d t) =
              SignKeySimpleKES (Vector (SignKeyDSIGN d))
        deriving Generic

    newtype SigKES (SimpleKES d t) =
              SigSimpleKES (SigDSIGN d)
        deriving Generic


    --
    -- Metadata and basic key operations
    --

    algorithmNameKES proxy = "simple_" ++ show (totalPeriodsKES proxy)

    deriveVerKeyKES (SignKeySimpleKES sks) =
        VerKeySimpleKES (Vec.map deriveVerKeyDSIGN sks)


    --
    -- Core algorithm operations
    --

    type ContextKES (SimpleKES d t) = DSIGN.ContextDSIGN d
    type Signable   (SimpleKES d t) = DSIGN.Signable     d

    signKES ctxt j a (SignKeySimpleKES sks) =
        case sks !? fromIntegral j of
          Nothing -> error ("SimpleKES.signKES: period out of range " ++ show j)
          Just sk -> SigSimpleKES (signDSIGN ctxt a sk)

    verifyKES ctxt (VerKeySimpleKES vks) j a (SigSimpleKES sig) =
        case vks !? fromIntegral j of
          Nothing -> Left "KES verification failed: out of range"
          Just vk -> verifyDSIGN ctxt vk a sig

    updateKES _ sk to
      | to >= fromIntegral (natVal (Proxy @ t)) = Nothing
      | otherwise                               = Just sk

    totalPeriodsKES  _ = fromIntegral (natVal (Proxy @ t))


    --
    -- Key generation
    --

    seedSizeKES _ =
        let seedSize = seedSizeDSIGN (Proxy :: Proxy d)
            duration = fromIntegral (natVal (Proxy @ t))
         in duration * seedSize

    genKeyKES seed =
        let seedSize = seedSizeDSIGN (Proxy :: Proxy d)
            duration = fromIntegral (natVal (Proxy @ t))
            seeds    = take duration
                     . map mkSeedFromBytes
                     $ unfoldr (getBytesFromSeed seedSize) seed
            sks      = map genKeyDSIGN seeds
         in SignKeySimpleKES (Vec.fromList sks)


    --
    -- CBOR encoding/decoding
    --

    encodeVerKeyKES = toCBOR
    encodeSignKeyKES = toCBOR
    encodeSigKES = toCBOR

    decodeSignKeyKES = fromCBOR
    decodeVerKeyKES = fromCBOR
    decodeSigKES = fromCBOR


deriving instance DSIGNAlgorithm d => Show (VerKeyKES (SimpleKES d t))

deriving instance DSIGNAlgorithm d => Eq (VerKeyKES (SimpleKES d t))

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => ToCBOR (VerKeyKES (SimpleKES d t)) where
  toCBOR (VerKeySimpleKES vks) =
      encodeListLen (fromIntegral $ Vec.length vks)
   <> foldr (\vk r -> encodeVerKeyDSIGN vk <> r) mempty vks

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => FromCBOR (VerKeyKES (SimpleKES d t)) where
  fromCBOR =
    VerKeySimpleKES <$> do
      len <- decodeListLen
      Vec.fromList <$> replicateM len decodeVerKeyDSIGN

deriving instance DSIGNAlgorithm d => Show (SignKeyKES (SimpleKES d t))

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => ToCBOR (SignKeyKES (SimpleKES d t)) where
  toCBOR (SignKeySimpleKES sks) =
      encodeListLen (fromIntegral (length sks))
   <> foldr (\sk r -> encodeSignKeyDSIGN sk <> r) mempty sks

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => FromCBOR (SignKeyKES (SimpleKES d t)) where
  fromCBOR =
    SignKeySimpleKES <$> do
      len <- decodeListLen
      Vec.fromList <$> replicateM len decodeSignKeyDSIGN

deriving instance DSIGNAlgorithm d => Show (SigKES (SimpleKES d t))
deriving instance DSIGNAlgorithm d => Eq   (SigKES (SimpleKES d t))

instance DSIGNAlgorithm d => NoUnexpectedThunks (SigKES     (SimpleKES d t))
instance DSIGNAlgorithm d => NoUnexpectedThunks (SignKeyKES (SimpleKES d t))
instance DSIGNAlgorithm d => NoUnexpectedThunks (VerKeyKES  (SimpleKES d t))

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => ToCBOR (SigKES (SimpleKES d t)) where
  toCBOR (SigSimpleKES d) = encodeSigDSIGN d

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => FromCBOR (SigKES (SimpleKES d t)) where
  fromCBOR = SigSimpleKES <$> decodeSigDSIGN
