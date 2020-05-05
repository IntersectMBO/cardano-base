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

import Control.Exception (assert)

import Cardano.Binary (FromCBOR (..), ToCBOR (..), decodeListLenOf, encodeListLen)
import Cardano.Crypto.Hash
import Cardano.Crypto.Seed
import Cardano.Crypto.KES.Class
import Cardano.Crypto.Util
import Cardano.Prelude (NoUnexpectedThunks)


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

    --
    -- Key and signature types
    --

    newtype VerKeyKES (MockKES t) = VerKeyMockKES Word64
        deriving stock   (Show, Eq, Ord, Generic)
        deriving newtype (NoUnexpectedThunks, ToCBOR, FromCBOR)

    data SignKeyKES (MockKES t) =
           SignKeyMockKES !(VerKeyKES (MockKES t)) !Period
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    data SigKES (MockKES t) =
           SigMockKES !(Hash MD5 ()) !(SignKeyKES (MockKES t))
        deriving stock    (Show, Eq, Ord, Generic)
        deriving anyclass (NoUnexpectedThunks)

    --
    -- Metadata and basic key operations
    --

    algorithmNameKES proxy = "mock_" ++ show (totalPeriodsKES proxy)

    deriveVerKeyKES (SignKeyMockKES vk _) = vk

    sizeVerKeyKES  _ = 8
    sizeSignKeyKES _ = 16
    sizeSigKES     _ = 32


    --
    -- Core algorithm operations
    --

    type Signable (MockKES t) = ToCBOR

    updateKES () (SignKeyMockKES vk k) to =
      assert (to >= k) $
         if to < totalPeriodsKES (Proxy @ (MockKES t))
           then Just (SignKeyMockKES vk to)
           else Nothing

    -- | Produce valid signature only with correct key, i.e., same iteration and
    -- allowed KES period.
    signKES () j a (SignKeyMockKES vk k)
        | j == k
        , j  < totalPeriodsKES (Proxy @ (MockKES t))
        = SigMockKES (castHash (hash a)) (SignKeyMockKES vk j)

        | otherwise
        = error ("MockKES.signKES: wrong period " ++ show j)

    verifyKES () vk j a (SigMockKES h (SignKeyMockKES vk' j')) =
        if    j  == j'
           && vk == vk'
           && castHash (hash a) == h
          then Right ()
          else Left "KES verification failed"

    totalPeriodsKES  _ = fromIntegral (natVal (Proxy @ t))

    --
    -- Key generation
    --

    seedSizeKES _ = 8
    genKeyKES seed =
        let vk = VerKeyMockKES (runMonadRandomWithSeed seed getRandomWord64)
         in SignKeyMockKES vk 0


    --
    -- raw serialise/deserialise
    --

    rawSerialiseVerKeyKES (VerKeyMockKES vk) =
        writeBinaryWord64 vk

    rawSerialiseSignKeyKES (SignKeyMockKES vk t) =
        rawSerialiseVerKeyKES vk
     <> writeBinaryWord64 (fromIntegral t)

    rawSerialiseSigKES (SigMockKES h sk) =
        getHash h
     <> rawSerialiseSignKeyKES sk

    rawDeserialiseVerKeyKES bs
      | [vkb] <- splitsAt [8] bs
      , let vk = readBinaryWord64 vkb
      = Just $! VerKeyMockKES vk

      | otherwise
      = Nothing

    rawDeserialiseSignKeyKES bs
      | [vkb, tb] <- splitsAt [8, 8] bs
      , Just vk   <- rawDeserialiseVerKeyKES vkb
      , let t      = fromIntegral (readBinaryWord64 tb)
      = Just $! SignKeyMockKES vk t

      | otherwise
      = Nothing

    rawDeserialiseSigKES bs
      | [hb, skb] <- splitsAt [16, 16] bs
      , Just h    <- hashFromBytes hb
      , Just sk   <- rawDeserialiseSignKeyKES skb
      = Just $! SigMockKES h sk

      | otherwise
      = Nothing


    --
    -- CBOR encoding/decoding
    --

    encodeVerKeyKES = toCBOR
    encodeSignKeyKES = toCBOR
    encodeSigKES = toCBOR

    decodeSignKeyKES = fromCBOR
    decodeVerKeyKES = fromCBOR
    decodeSigKES = fromCBOR


instance KnownNat t => ToCBOR (SigKES (MockKES t)) where
  toCBOR (SigMockKES evolution key) =
    encodeListLen 2 <>
      toCBOR evolution <>
      toCBOR key

instance KnownNat t => FromCBOR (SigKES (MockKES t)) where
  fromCBOR =
    SigMockKES <$
      decodeListLenOf 2 <*>
      fromCBOR <*>
      fromCBOR

instance KnownNat t => ToCBOR (SignKeyKES (MockKES t)) where
  toCBOR (SignKeyMockKES vk k) =
    encodeListLen 2 <>
      toCBOR vk <>
      toCBOR k

instance KnownNat t => FromCBOR (SignKeyKES (MockKES t)) where
  fromCBOR =
    SignKeyMockKES <$
      decodeListLenOf 2 <*>
      fromCBOR <*>
      fromCBOR
