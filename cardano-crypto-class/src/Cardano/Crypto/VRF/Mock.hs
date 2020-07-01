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
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  newtype SignKeyVRF MockVRF = SignKeyMockVRF Word64
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  newtype CertVRF MockVRF = CertMockVRF Word64
      deriving (Show, Eq, Ord, Generic, NoUnexpectedThunks)

  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF _ = "mock"

  deriveVerKeyVRF (SignKeyMockVRF n) = VerKeyMockVRF n


  --
  -- Core algorithm operations
  --

  type Signable MockVRF = ToCBOR

  evalVRF () a sk = evalVRF' a sk

  verifyVRF () (VerKeyMockVRF n) a c = evalVRF' a (SignKeyMockVRF n) == c

  sizeOutputVRF _ = sizeHash (Proxy :: Proxy MD5)

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

  sizeVerKeyVRF  _ = 8
  sizeSignKeyVRF _ = 8
  sizeCertVRF    _ = 8

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


instance ToCBOR (VerKeyVRF MockVRF) where
  toCBOR = encodeVerKeyVRF
  encodedSizeExpr _size = encodedVerKeyVRFSizeExpr

instance FromCBOR (VerKeyVRF MockVRF) where
  fromCBOR = decodeVerKeyVRF

instance ToCBOR (SignKeyVRF MockVRF) where
  toCBOR = encodeSignKeyVRF
  encodedSizeExpr _size = encodedSignKeyVRFSizeExpr

instance FromCBOR (SignKeyVRF MockVRF) where
  fromCBOR = decodeSignKeyVRF

instance ToCBOR (CertVRF MockVRF) where
  toCBOR = encodeCertVRF
  encodedSizeExpr _size = encodedCertVRFSizeExpr

instance FromCBOR (CertVRF MockVRF) where
  fromCBOR = decodeCertVRF


evalVRF' :: ToCBOR a
         => a
         -> SignKeyVRF MockVRF
         -> (OutputVRF MockVRF, CertVRF MockVRF)
evalVRF' a sk@(SignKeyMockVRF n) =
  let y = getHash $ hashWithSerialiser @MD5 id $ toCBOR a <> toCBOR sk
  in (OutputVRF y, CertMockVRF n)
