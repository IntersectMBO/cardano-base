{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock implementations of verifiable random functions.
module Cardano.Crypto.VRF.Mock (
  MockVRF,
  VerKeyVRF (..),
  SignKeyVRF (..),
)
where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  guardFixedSized,
 )
import Control.DeepSeq (NFData)
import Data.Proxy (Proxy (..))
import Data.Word (Word64)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.Hash
import Cardano.Crypto.Seed
import Cardano.Crypto.Util
import Cardano.Crypto.VRF.Class

data MockVRF

instance VRFAlgorithm MockVRF where
  --
  -- Key and signature types
  --

  newtype VerKeyVRF MockVRF = VerKeyMockVRF Word64
    deriving (Show, Eq, Ord, Generic, NoThunks, NFData)

  newtype SignKeyVRF MockVRF = SignKeyMockVRF Word64
    deriving (Show, Eq, Ord, Generic, NoThunks, NFData)

  newtype CertVRF MockVRF = CertMockVRF Word64
    deriving (Show, Eq, Ord, Generic, NoThunks, NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF _ = "mock"

  deriveVerKeyVRF (SignKeyMockVRF n) = VerKeyMockVRF n

  --
  -- Core algorithm operations
  --

  type Signable MockVRF = SignableRepresentation

  evalVRF () a sk = evalVRF' a sk

  verifyVRF () (VerKeyMockVRF n) a c
    | c == c' = Just o
    | otherwise = Nothing
    where
      (o, c') = evalVRF' a (SignKeyMockVRF n)

  sizeOutputVRF _ = hashSize (Proxy :: Proxy ShortHash)

  --
  -- Key generation
  --

  seedSizeVRF _ = 8
  genKeyVRF seed = SignKeyMockVRF sk
    where
      sk = runMonadRandomWithSeed seed getRandomWord64

instance ToCBOR (VerKeyVRF MockVRF) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedVerKeyVRFSizeExpr

instance FromCBOR (VerKeyVRF MockVRF) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyVRF MockVRF) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedSignKeyVRFSizeExpr

instance FromCBOR (SignKeyVRF MockVRF) where
  fromCBOR = decodeFixedSized

instance ToCBOR (CertVRF MockVRF) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _size = encodedCertVRFSizeExpr

instance FromCBOR (CertVRF MockVRF) where
  fromCBOR = decodeFixedSized

instance FixedSizeCodec (VerKeyVRF MockVRF) where
  type FixedSize (VerKeyVRF MockVRF) = 8
  rawEncodeFixedSized (VerKeyMockVRF k) = writeBinaryWord64 k
  rawDecodeFixedSized bs = guardFixedSized bs $ pure $! VerKeyMockVRF (readBinaryWord64 bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyVRF MockVRF) where
  type FixedSize (SignKeyVRF MockVRF) = 8
  rawEncodeFixedSized (SignKeyMockVRF k) = writeBinaryWord64 k
  rawDecodeFixedSized bs = guardFixedSized bs $ pure $! SignKeyMockVRF (readBinaryWord64 bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (CertVRF MockVRF) where
  type FixedSize (CertVRF MockVRF) = 8
  rawEncodeFixedSized (CertMockVRF k) = writeBinaryWord64 k
  rawDecodeFixedSized bs = guardFixedSized bs $ pure $! CertMockVRF (readBinaryWord64 bs)
  {-# INLINE rawDecodeFixedSized #-}

evalVRF' ::
  SignableRepresentation a =>
  a ->
  SignKeyVRF MockVRF ->
  (OutputVRF MockVRF, CertVRF MockVRF)
evalVRF' a sk@(SignKeyMockVRF n) =
  let y =
        hashToByteArray $
          hashWithSerialiser @ShortHash id $
            toCBOR (getSignableRepresentation a) <> toCBOR sk
   in (OutputVRF y, CertMockVRF n)
