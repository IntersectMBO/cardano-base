{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock implementations of verifiable random functions.
module Cardano.Crypto.VRF.Mock
  ( MockVRF
  , VerKeyVRF (..)
  , SignKeyVRF (..)
  )
where

import Data.Word (Word64)
import Numeric.Natural (Natural)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)

import Cardano.Prelude (NoUnexpectedThunks)
import Cardano.Binary (FromCBOR, ToCBOR (..), FromCBOR(..))

import Cardano.Crypto.Hash
import Cardano.Crypto.Util
import Cardano.Crypto.Seed
import Cardano.Crypto.VRF.Class


data MockVRF

instance VRFAlgorithm MockVRF where

  --
  -- Key and signature types
  --

  newtype VerKeyVRF MockVRF = VerKeyMockVRF Word64
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

  newtype SignKeyVRF MockVRF = SignKeyMockVRF Word64
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

  newtype CertVRF MockVRF = CertMockVRF Word64
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks, ToCBOR, FromCBOR)

  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF _ = "mock"

  deriveVerKeyVRF (SignKeyMockVRF n) = VerKeyMockVRF n

  sizeVerKeyVRF  _ = 8
  sizeSignKeyVRF _ = 8
  sizeCertVRF    _ = 8


  --
  -- Core algorithm operations
  --

  type Signable MockVRF = ToCBOR

  evalVRF () a sk = return $ evalVRF' a sk

  verifyVRF () (VerKeyMockVRF n) a c = evalVRF' a (SignKeyMockVRF n) == c

  maxVRF _ = 2 ^ (8 * sizeHash (Proxy :: Proxy MD5)) - 1

  --
  -- Key generation
  --

  seedSizeVRF _  = 8
  genKeyVRF seed = SignKeyMockVRF sk
    where
      sk = runMonadRandomWithSeed seed getRandomWord64


  --
  -- raw serialise/deserialise
  --

  rawSerialiseVerKeyVRF  (VerKeyMockVRF  k) = writeBinaryWord64 k
  rawSerialiseSignKeyVRF (SignKeyMockVRF k) = writeBinaryWord64 k
  rawSerialiseCertVRF    (CertMockVRF    k) = writeBinaryWord64 k

  rawDeserialiseVerKeyVRF bs
    | [kb] <- splitsAt [8] bs
    , let k = readBinaryWord64 kb
    = Just $! VerKeyMockVRF k

    | otherwise
    = Nothing

  rawDeserialiseSignKeyVRF bs
    | [kb] <- splitsAt [8] bs
    , let k = readBinaryWord64 kb
    = Just $! SignKeyMockVRF k

    | otherwise
    = Nothing

  rawDeserialiseCertVRF bs
    | [kb] <- splitsAt [8] bs
    , let k = readBinaryWord64 kb
    = Just $! CertMockVRF k

    | otherwise
    = Nothing


  --
  -- CBOR encoding/decoding
  --

  encodeVerKeyVRF  = toCBOR
  decodeVerKeyVRF  = fromCBOR
  encodeSignKeyVRF = toCBOR
  decodeSignKeyVRF = fromCBOR
  encodeCertVRF    = toCBOR
  decodeCertVRF    = fromCBOR


evalVRF' :: ToCBOR a => a -> SignKeyVRF MockVRF -> (Natural, CertVRF MockVRF)
evalVRF' a sk@(SignKeyMockVRF n) =
  let y = fromHash $ hashWithSerialiser @MD5 id $ toCBOR a <> toCBOR sk
  in (y, CertMockVRF n)
