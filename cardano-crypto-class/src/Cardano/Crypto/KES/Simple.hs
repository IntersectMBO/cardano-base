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
import Data.List (unfoldr)
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import Data.Vector ((!?), Vector, fromList)
import qualified Data.Vector as Vec
import GHC.Generics (Generic)
import GHC.TypeNats (Nat, KnownNat, natVal)
import Numeric.Natural (Natural)
import Control.Exception (assert)

data SimpleKES d (t :: Nat)

instance (DSIGNAlgorithm d, Typeable d, KnownNat t) =>
         KESAlgorithm (SimpleKES d t) where

    newtype VerKeyKES (SimpleKES d t) =
              VerKeySimpleKES (Vector (VerKeyDSIGN d))
        deriving Generic

    newtype SignKeyKES (SimpleKES d t) =
        SignKeySimpleKES ([VerKeyDSIGN d], [(Natural, SignKeyDSIGN d)])
        deriving Generic

    newtype SigKES (SimpleKES d t) = SigSimpleKES (SigDSIGN d)
        deriving (Generic)

    type Signable   (SimpleKES d t) = DSIGN.Signable     d
    type ContextKES (SimpleKES d t) = DSIGN.ContextDSIGN d

    encodeVerKeyKES = toCBOR
    encodeSignKeyKES = toCBOR
    encodeSigKES = toCBOR

    decodeSignKeyKES = fromCBOR
    decodeVerKeyKES = fromCBOR
    decodeSigKES = fromCBOR

    seedSizeKES _ =
        let seedSize = seedSizeDSIGN (Proxy :: Proxy d)
            duration = natVal (Proxy @ t)
         in duration * seedSize

    genKeyKES seed =
        let seedSize = fromIntegral (seedSizeDSIGN (Proxy :: Proxy d))
            duration = natVal (Proxy @ t)
            seeds = take (fromIntegral duration)
                  . map mkSeedFromBytes
                  $ unfoldr (getBytesFromSeed seedSize) seed
            sks = map genKeyDSIGN seeds
            vks = map deriveVerKeyDSIGN sks
         in SignKeySimpleKES (vks, zip [0..] sks)

    deriveVerKeyKES (SignKeySimpleKES (vks, _)) = VerKeySimpleKES $ fromList vks

    signKES ctxt j a (SignKeySimpleKES (_, xs)) = case dropWhile (\(k, _) -> k < j) xs of
        []          -> Nothing
        (_, sk) : _ -> Just (SigSimpleKES sig)
                         where sig = signDSIGN ctxt a sk

    verifyKES ctxt (VerKeySimpleKES vks) j a (SigSimpleKES sig) =
        case vks !? fromIntegral j of
            Nothing -> Left "KES verification failed: out of range"
            Just vk -> verifyDSIGN ctxt vk a sig

    updateKES _ (SignKeySimpleKES (_, [])) _ = Nothing
    updateKES ctx s@(SignKeySimpleKES (vks, sks)) to =
      assert (to >= currentPeriodKES ctx s) $
      let sks' = dropWhile (\(d', _) -> to /= d') sks in
        case sks' of
          [] -> Nothing
          _  -> Just (SignKeySimpleKES (vks, sks'))

    currentPeriodKES _ (SignKeySimpleKES (_, [])) = error "no KES key available"
    currentPeriodKES _ (SignKeySimpleKES (_, (d, _) : _)) = d

    totalPeriodsKES  _ = natVal (Proxy @ t)

deriving instance DSIGNAlgorithm d => Show (VerKeyKES (SimpleKES d t))

deriving instance DSIGNAlgorithm d => Eq (VerKeyKES (SimpleKES d t))

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => ToCBOR (VerKeyKES (SimpleKES d t)) where
  toCBOR (VerKeySimpleKES vvks) =
    encodeListLen (fromIntegral $ Vec.length vvks) <>
      Vec.foldl' (<>) mempty (fmap encodeVerKeyDSIGN vvks)

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => FromCBOR (VerKeyKES (SimpleKES d t)) where
  fromCBOR =
    VerKeySimpleKES <$> do
      len <- decodeListLen
      Vec.fromList <$> replicateM len decodeVerKeyDSIGN

deriving instance DSIGNAlgorithm d => Show (SignKeyKES (SimpleKES d t))

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => ToCBOR (SignKeyKES (SimpleKES d t)) where
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

instance (DSIGNAlgorithm d, Typeable d, KnownNat t)
      => FromCBOR (SignKeyKES (SimpleKES d t)) where
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
