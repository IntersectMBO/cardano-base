{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock key evolving signatures.
module Cardano.Crypto.KES.Mock
  ( MockKES
  , VerKeyKES (..)
  , SignKeyKES (..)
  , SigKES (..)
  )
where

import Data.Word (Word64)
import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)
import GHC.TypeNats (Nat, KnownNat, natVal)
import NoThunks.Class (NoThunks)

import Cardano.Prelude (Identity)

import Control.Exception (assert)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash
import Cardano.Crypto.Seed
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Util
import Cardano.Crypto.Libsodium (mlsbToByteString)

data MockKES (t :: Nat)

-- | Mock key evolving signatures.
--
-- What is the difference between Mock KES and Simple KES
-- (@Cardano.Crypto.KES.Simple@), you may ask? Simple KES satisfies the outward
-- appearance of a KES scheme through assembling a pre-generated list of keys
-- and iterating through them. Mock KES, on the other hand, pretends to be KES
-- but in fact does no key evolution whatsoever.
--
-- Simple KES is appropriate for testing, since it will for example reject old
-- keys. Mock KES is more suitable for a basic testnet, since it doesn't suffer
-- from the performance implications of shuffling a giant list of keys around
instance KnownNat t => KESAlgorithm (MockKES t) where
    type SeedSizeKES (MockKES t) = 8

    type SignKeyAccessKES (MockKES t) = Identity

    --
    -- Key and signature types
    --

    newtype VerKeyKES (MockKES t) = VerKeyMockKES Word64
        deriving stock   (Show, Eq, Generic)
        deriving newtype (NoThunks)

    data SignKeyKES (MockKES t) =
           SignKeyMockKES !(VerKeyKES (MockKES t)) !Period
        deriving stock    (Show, Eq, Generic)
        deriving anyclass (NoThunks)

    data SigKES (MockKES t) =
           SigMockKES !(Hash MD5 ()) !(SignKeyKES (MockKES t))
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoThunks)

    --
    -- Metadata and basic key operations
    --

    algorithmNameKES proxy = "mock_" ++ show (totalPeriodsKES proxy)

    deriveVerKeyKES (SignKeyMockKES vk _) = return vk

    sizeVerKeyKES  _ = 8
    sizeSignKeyKES _ = 16
    sizeSigKES     _ = 32


    --
    -- Core algorithm operations
    --

    type Signable (MockKES t) = SignableRepresentation

    updateKES () (SignKeyMockKES vk t') t =
        assert (t == t') $
         if t+1 < totalPeriodsKES (Proxy @ (MockKES t))
           then return $ Just (SignKeyMockKES vk (t+1))
           else return Nothing

    -- | Produce valid signature only with correct key, i.e., same iteration and
    -- allowed KES period.
    signKES () t a (SignKeyMockKES vk t') =
        assert (t == t') $
        return $
        SigMockKES (castHash (hashWith getSignableRepresentation a))
                   (SignKeyMockKES vk t)

    verifyKES () vk t a (SigMockKES h (SignKeyMockKES vk' t'))
      | t' == t
      , vk == vk'
      , castHash (hashWith getSignableRepresentation a) == h
      = Right ()

      | otherwise
      = Left "KES verification failed"

    totalPeriodsKES  _ = fromIntegral (natVal (Proxy @ t))


    --
    -- Key generation
    --

    genKeyKES seed = do
        let vk = VerKeyMockKES (runMonadRandomWithSeed (mkSeedFromBytes $ mlsbToByteString seed) getRandomWord64)
        return $ SignKeyMockKES vk 0


    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyKES (VerKeyMockKES vk) =
        writeBinaryWord64 vk

    rawSerialiseSigKES (SigMockKES h (SignKeyMockKES k t)) =
        hashToBytes h
     <> rawSerialiseVerKeyKES k
     <> writeBinaryWord64 (fromIntegral t)

    rawSerialiseSignKeyKES (SignKeyMockKES vk t) = return $
        rawSerialiseVerKeyKES vk
     <> writeBinaryWord64 (fromIntegral t)

    rawDeserialiseVerKeyKES bs
      | [vkb] <- splitsAt [8] bs
      , let vk = readBinaryWord64 vkb
      = Just $! VerKeyMockKES vk

      | otherwise
      = Nothing

    rawDeserialiseSigKES bs
      | [hb, kb, tb] <- splitsAt [16, 8, 8] bs
      , Just h    <- hashFromBytes hb
      , Just k    <- rawDeserialiseVerKeyKES kb
      , t    <- fromIntegral (readBinaryWord64 tb)
      = Just $! SigMockKES h (SignKeyMockKES k t)

      | otherwise
      = Nothing

    rawDeserialiseSignKeyKES bs
      | [vkb, tb] <- splitsAt [8, 8] bs
      , Just vk   <- rawDeserialiseVerKeyKES vkb
      , let t      = fromIntegral (readBinaryWord64 tb)
      = return . Just $! SignKeyMockKES vk t

      | otherwise
      = return Nothing




instance KnownNat t => ToCBOR (VerKeyKES (MockKES t)) where
  toCBOR = encodeVerKeyKES
  encodedSizeExpr _size = encodedVerKeyKESSizeExpr

instance KnownNat t => FromCBOR (VerKeyKES (MockKES t)) where
  fromCBOR = decodeVerKeyKES

instance KnownNat t => ToCBOR (SigKES (MockKES t)) where
  toCBOR = encodeSigKES
  encodedSizeExpr _size = encodedSigKESSizeExpr

instance KnownNat t => FromCBOR (SigKES (MockKES t)) where
  fromCBOR = decodeSigKES

