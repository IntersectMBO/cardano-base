{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Simple
  ( SimpleKES
  , SigKES (..)
  , SignKeyKES (..)
  )
where

import Cardano.Binary
  ( Decoder
  , Encoding
  , FromCBOR (..)
  , ToCBOR (..)
  , decodeListLen
  , decodeListLenOf
  , decodeWord
  , encodeListLen
  , encodeWord
  )

import Cardano.Crypto.DSIGN
import qualified Cardano.Crypto.DSIGN as DSIGN
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Seed
import Cardano.Prelude (NoUnexpectedThunks)
import Control.Monad (replicateM)
import Crypto.Random (MonadRandom(getRandomBytes))
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import Data.Vector ((!?), Vector, fromList)
import qualified Data.Vector as Vec
import GHC.Generics (Generic)
import Numeric.Natural (Natural)
import Control.Exception (assert)

data SimpleKES d

instance (DSIGNAlgorithm d, Typeable d) => KESAlgorithm (SimpleKES d) where

    newtype VerKeyKES (SimpleKES d) = VerKeySimpleKES (Vector (VerKeyDSIGN d))
        deriving Generic

    newtype SignKeyKES (SimpleKES d) =
        SignKeySimpleKES ([VerKeyDSIGN d], [(Natural, SignKeyDSIGN d)])
        deriving Generic

    newtype SigKES (SimpleKES d) = SigSimpleKES (SigDSIGN d)
        deriving (Generic)

    type Signable   (SimpleKES d) = DSIGN.Signable     d
    type ContextKES (SimpleKES d) = DSIGN.ContextDSIGN d

    encodeVerKeyKES = toCBOR
    encodeSignKeyKES = toCBOR
    encodeSigKES = toCBOR

    decodeSignKeyKES = fromCBOR
    decodeVerKeyKES = fromCBOR
    decodeSigKES = fromCBOR

    genKeyKES duration = do
        let seedSize = fromIntegral (seedSizeDSIGN (Proxy :: Proxy d))
        seeds <- replicateM (fromIntegral duration)
                            (mkSeedFromBytes <$> getRandomBytes seedSize)
        let sks = map genKeyDSIGN seeds
        let vks = map deriveVerKeyDSIGN sks
        return $ SignKeySimpleKES (vks, zip [0..] sks)

    deriveVerKeyKES (SignKeySimpleKES (vks, _)) = VerKeySimpleKES $ fromList vks

    signKES ctxt j a (SignKeySimpleKES (_, xs)) = case dropWhile (\(k, _) -> k < j) xs of
        []          -> return Nothing
        (_, sk) : _ -> return $ Just (SigSimpleKES sig)
                         where sig = signDSIGN ctxt a sk

    verifyKES ctxt (VerKeySimpleKES vks) j a (SigSimpleKES sig) =
        case vks !? fromIntegral j of
            Nothing -> Left "KES verification failed: out of range"
            Just vk -> verifyDSIGN ctxt vk a sig

    updateKES _ (SignKeySimpleKES (_, [])) _ = pure Nothing
    updateKES ctx s@(SignKeySimpleKES (vks, sks)) to =
      assert (to >= currentPeriodKES ctx s) $
      let sks' = dropWhile (\(d', _) -> to /= d') sks in
        case sks' of
          [] -> pure Nothing
          _  -> pure $ Just (SignKeySimpleKES (vks, sks'))

    currentPeriodKES _ (SignKeySimpleKES (_, [])) = error "no KES key available"
    currentPeriodKES _ (SignKeySimpleKES (_, (d, _) : _)) = d

deriving instance DSIGNAlgorithm d => Show (VerKeyKES (SimpleKES d))

deriving instance DSIGNAlgorithm d => Eq (VerKeyKES (SimpleKES d))

instance (DSIGNAlgorithm d, Typeable d) => ToCBOR (VerKeyKES (SimpleKES d)) where
  toCBOR (VerKeySimpleKES vvks) =
    encodeListLen (fromIntegral $ Vec.length vvks) <>
      Vec.foldl' (<>) mempty (fmap encodeVerKeyDSIGN vvks)

instance (DSIGNAlgorithm d, Typeable d) => FromCBOR (VerKeyKES (SimpleKES d)) where
  fromCBOR =
    VerKeySimpleKES <$> do
      len <- decodeListLen
      Vec.fromList <$> replicateM len decodeVerKeyDSIGN

deriving instance DSIGNAlgorithm d => Show (SignKeyKES (SimpleKES d))

instance (DSIGNAlgorithm d, Typeable d) => ToCBOR (SignKeyKES (SimpleKES d)) where
  toCBOR (SignKeySimpleKES (vks, stuff)) =
    encodeListLen 2 <>
      encodeListLen (fromIntegral $ length vks) <>
      mconcat (fmap encodeVerKeyDSIGN vks) <>
      encodeListLen (fromIntegral $ length stuff) <>
      mconcat (fmap encodeStuff stuff)
    where
      encodeStuff :: (Natural, SignKeyDSIGN d) -> Encoding
      encodeStuff (n, skd) =
        encodeListLen 2 <>
          encodeWord (fromIntegral n) <>
          encodeSignKeyDSIGN skd

instance (DSIGNAlgorithm d, Typeable d) => FromCBOR (SignKeyKES (SimpleKES d)) where
  fromCBOR =
    SignKeySimpleKES <$> do
      decodeListLenOf 2
      vksLen <- decodeListLen
      vks <- replicateM vksLen decodeVerKeyDSIGN
      stuffLen <- decodeListLen
      stuff <- replicateM stuffLen decodeStuff
      return (vks, stuff)
    where
      decodeStuff :: Decoder s (Natural, SignKeyDSIGN d)
      decodeStuff = do
        decodeListLenOf 2
        n <- fromIntegral <$> decodeWord
        sks <- decodeSignKeyDSIGN
        return (n, sks)

deriving instance DSIGNAlgorithm d => Show (SigKES (SimpleKES d))
deriving instance DSIGNAlgorithm d => Eq   (SigKES (SimpleKES d))

instance DSIGNAlgorithm d => NoUnexpectedThunks (SigKES     (SimpleKES d))
instance DSIGNAlgorithm d => NoUnexpectedThunks (SignKeyKES (SimpleKES d))
instance DSIGNAlgorithm d => NoUnexpectedThunks (VerKeyKES  (SimpleKES d))

instance (DSIGNAlgorithm d, Typeable d) => ToCBOR (SigKES (SimpleKES d)) where
  toCBOR (SigSimpleKES d) = encodeSigDSIGN d

instance (DSIGNAlgorithm d, Typeable d) => FromCBOR (SigKES (SimpleKES d)) where
  fromCBOR = SigSimpleKES <$> decodeSigDSIGN
