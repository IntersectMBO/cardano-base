{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Abstract Verifiable Random Functions.
module Cardano.Crypto.VRF.Class (
  -- * VRF algorithm class
  VRFAlgorithm (..),
  sizeVerKeyVRF,
  sizeSignKeyVRF,
  sizeCertVRF,

  -- ** VRF output
  OutputVRF (..),
  getOutputVRFBytes,
  getOutputVRFNatural,
  mkTestOutputVRF,

  -- * 'CertifiedVRF' wrapper
  CertifiedVRF (..),
  evalCertified,
  verifyCertified,

  -- * CBOR encoding and decoding
  encodeVerKeyVRF,
  decodeVerKeyVRF,
  encodeSignKeyVRF,
  decodeSignKeyVRF,
  encodeCertVRF,
  decodeCertVRF,

  -- * Encoded 'Size' expressions
  encodedVerKeyVRFSizeExpr,
  encodedSignKeyVRFSizeExpr,
  encodedCertVRFSizeExpr,
)
where

import Cardano.Binary (
  Decoder,
  Encoding,
  FromCBOR (..),
  Size,
  ToCBOR (..),
  encodeBytes,
  encodeListLen,
  enforceSize,
  withWordSize,
 )
import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  fixedSize,
 )
import Cardano.Crypto.Hash.Class (Hash, HashAlgorithm, hashWith)
import Cardano.Crypto.Seed (Seed)
import Cardano.Crypto.Util (Empty, byteArrayToNatural, naturalToByteArray)
import Control.DeepSeq (NFData)
import Data.Array.Byte (ByteArray)
import Data.ByteString (ByteString)
import Data.ByteString.Short as SBS (fromShort)
import Data.Kind (Type)
import Data.MemPack.Buffer (byteArrayToShortByteString)
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack
import GHC.TypeLits (ErrorMessage (..), KnownNat, Nat, TypeError)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import Numeric.Natural (Natural)

class
  ( Typeable v
  , Show (VerKeyVRF v)
  , Eq (VerKeyVRF v)
  , NFData (VerKeyVRF v)
  , Show (SignKeyVRF v)
  , NFData (SignKeyVRF v)
  , Show (CertVRF v)
  , Ord (CertVRF v)
  , NFData (CertVRF v)
  , NoThunks (CertVRF v)
  , NoThunks (VerKeyVRF v)
  , NoThunks (SignKeyVRF v)
  , KnownNat (VerKeySizeVRF v)
  , KnownNat (SignKeySizeVRF v)
  , KnownNat (CertSizeVRF v)
  , FixedSizeCodec (CertVRF v)
  , FixedSizeCodec (VerKeyVRF v)
  , FixedSizeCodec (SignKeyVRF v)
  ) =>
  VRFAlgorithm v
  where
  --
  -- Key and signature types
  --

  data VerKeyVRF v :: Type
  data SignKeyVRF v :: Type
  data CertVRF v :: Type

  type VerKeySizeVRF v :: Nat
  type VerKeySizeVRF v = FixedSize (VerKeyVRF v)
  type SignKeySizeVRF v :: Nat
  type SignKeySizeVRF v = FixedSize (SignKeyVRF v)
  type CertSizeVRF v :: Nat
  type CertSizeVRF v = FixedSize (CertVRF v)

  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF :: proxy v -> String

  deriveVerKeyVRF :: SignKeyVRF v -> VerKeyVRF v

  hashVerKeyVRF :: HashAlgorithm h => VerKeyVRF v -> Hash h (VerKeyVRF v)
  hashVerKeyVRF = hashWith rawEncodeFixedSized

  --
  -- Core algorithm operations
  --

  -- | Context required to run the VRF algorithm
  --
  -- Unit by default (no context required)
  type ContextVRF v :: Type

  type ContextVRF v = ()

  type Signable v :: Type -> Constraint
  type Signable c = Empty

  evalVRF ::
    (HasCallStack, Signable v a) =>
    ContextVRF v ->
    a ->
    SignKeyVRF v ->
    (OutputVRF v, CertVRF v)

  verifyVRF ::
    (HasCallStack, Signable v a) =>
    ContextVRF v ->
    VerKeyVRF v ->
    a ->
    CertVRF v ->
    Maybe (OutputVRF v)

  --
  -- Key generation
  --

  genKeyVRF :: Seed -> SignKeyVRF v
  genKeyPairVRF :: Seed -> (SignKeyVRF v, VerKeyVRF v)

  genKeyVRF =
    fst . genKeyPairVRF

  genKeyPairVRF = \seed ->
    let sk = genKeyVRF seed
     in (sk, deriveVerKeyVRF sk)

  -- | The upper bound on the 'Seed' size needed by 'genKeyVRF', in bytes.
  seedSizeVRF :: proxy v -> Word

  --
  -- Serialisation/(de)serialisation in fixed-size raw format
  --

  sizeOutputVRF :: proxy v -> Word

  rawSerialiseVerKeyVRF :: VerKeyVRF v -> ByteString
  rawSerialiseVerKeyVRF = rawEncodeFixedSized
  rawSerialiseSignKeyVRF :: SignKeyVRF v -> ByteString
  rawSerialiseSignKeyVRF = rawEncodeFixedSized
  rawSerialiseCertVRF :: CertVRF v -> ByteString
  rawSerialiseCertVRF = rawEncodeFixedSized

  rawDeserialiseVerKeyVRF :: ByteString -> Maybe (VerKeyVRF v)
  rawDeserialiseVerKeyVRF = rawDecodeFixedSized
  rawDeserialiseSignKeyVRF :: ByteString -> Maybe (SignKeyVRF v)
  rawDeserialiseSignKeyVRF = rawDecodeFixedSized
  rawDeserialiseCertVRF :: ByteString -> Maybe (CertVRF v)
  rawDeserialiseCertVRF = rawDecodeFixedSized

  {-# MINIMAL
    algorithmNameVRF
    , deriveVerKeyVRF
    , evalVRF
    , verifyVRF
    , seedSizeVRF
    , (genKeyVRF | genKeyPairVRF)
    , sizeOutputVRF
    #-}

{-# DEPRECATED rawSerialiseVerKeyVRF "Use `rawEncodeFixedSized` instead" #-}
{-# DEPRECATED rawSerialiseSignKeyVRF "Use `rawEncodeFixedSized` instead" #-}
{-# DEPRECATED rawSerialiseCertVRF "Use `rawEncodeFixedSized` instead" #-}
{-# DEPRECATED rawDeserialiseVerKeyVRF "Use `rawDecodeFixedSized` instead" #-}
{-# DEPRECATED rawDeserialiseSignKeyVRF "Use `rawDecodeFixedSized` instead" #-}
{-# DEPRECATED rawDeserialiseCertVRF "Use `rawDecodeFixedSized` instead" #-}

sizeVerKeyVRF ::
  forall v proxy. FixedSizeCodec (VerKeyVRF v) => proxy v -> Word
sizeVerKeyVRF _ = fixedSize $ Proxy @(VerKeyVRF v)
{-# DEPRECATED sizeVerKeyVRF "Use `fixedSize` instead" #-}

sizeSignKeyVRF :: forall v proxy. FixedSizeCodec (SignKeyVRF v) => proxy v -> Word
sizeSignKeyVRF _ = fixedSize $ Proxy @(SignKeyVRF v)
{-# DEPRECATED sizeSignKeyVRF "Use `fixedSize` instead" #-}

sizeCertVRF :: forall v proxy. FixedSizeCodec (CertVRF v) => proxy v -> Word
sizeCertVRF _ = fixedSize $ Proxy @(CertVRF v)
{-# DEPRECATED sizeCertVRF "Use `fixedSize` instead" #-}

--
-- Do not provide Ord instances for keys, see #38
--

instance
  ( TypeError ('Text "Ord not supported for signing keys, use the hash instead")
  , Eq (SignKeyVRF v)
  ) =>
  Ord (SignKeyVRF v)
  where
  compare = error "unsupported"

instance
  ( TypeError ('Text "Ord not supported for verification keys, use the hash instead")
  , Eq (VerKeyVRF v)
  ) =>
  Ord (VerKeyVRF v)
  where
  compare = error "unsupported"

-- | The output bytes of the VRF.
--
-- The output size is a fixed number of bytes and is given by 'sizeOutputVRF'.
newtype OutputVRF v = OutputVRF {getOutputVRFByteArray :: ByteArray}
  deriving (Eq, Ord, Show, ToCBOR, FromCBOR)
  deriving newtype (NFData)

-- ByteArray is already in NF
deriving via
  OnlyCheckWhnfNamed "OutputVRF" (OutputVRF v)
  instance
    NoThunks (OutputVRF v)

getOutputVRFBytes :: OutputVRF v -> ByteString
getOutputVRFBytes = SBS.fromShort . byteArrayToShortByteString . getOutputVRFByteArray

-- | The output bytes of the VRF interpreted as a big endian natural number.
--
-- The range of this number is determined by the size of the VRF output bytes.
-- It is thus in the range @0 ..  2 ^ (8 * sizeOutputVRF proxy) - 1@.
getOutputVRFNatural :: OutputVRF v -> Natural
getOutputVRFNatural = byteArrayToNatural . getOutputVRFByteArray

-- | For testing purposes, make an 'OutputVRF' from a 'Natural'.
--
-- The 'OutputVRF' will be of the appropriate size for the 'VRFAlgorithm'.
mkTestOutputVRF :: forall v. VRFAlgorithm v => Natural -> OutputVRF v
mkTestOutputVRF = OutputVRF . naturalToByteArray sz
  where
    sz = fromIntegral @Word @Int (sizeOutputVRF (Proxy :: Proxy v))

--
-- Convenient CBOR encoding/decoding
--
-- Implementations in terms of the raw (de)serialise
--

encodeVerKeyVRF :: VRFAlgorithm v => VerKeyVRF v -> Encoding
encodeVerKeyVRF = encodeBytes . rawEncodeFixedSized
{-# DEPRECATED encodeVerKeyVRF "Use `encodeFixedSized` instead" #-}

encodeSignKeyVRF :: VRFAlgorithm v => SignKeyVRF v -> Encoding
encodeSignKeyVRF = encodeBytes . rawEncodeFixedSized
{-# DEPRECATED encodeSignKeyVRF "Use `encodeFixedSized` instead" #-}

encodeCertVRF :: VRFAlgorithm v => CertVRF v -> Encoding
encodeCertVRF = encodeBytes . rawEncodeFixedSized
{-# DEPRECATED encodeCertVRF "Use `encodeFixedSized` instead" #-}

decodeVerKeyVRF :: forall v s. VRFAlgorithm v => Decoder s (VerKeyVRF v)
decodeVerKeyVRF = decodeFixedSized
{-# INLINE decodeVerKeyVRF #-}
{-# DEPRECATED decodeVerKeyVRF "Use `decodeFixedSized` instead" #-}

decodeSignKeyVRF :: forall v s. VRFAlgorithm v => Decoder s (SignKeyVRF v)
decodeSignKeyVRF = decodeFixedSized
{-# INLINE decodeSignKeyVRF #-}
{-# DEPRECATED decodeSignKeyVRF "Use `decodeFixedSized` instead" #-}

decodeCertVRF :: forall v s. VRFAlgorithm v => Decoder s (CertVRF v)
decodeCertVRF = decodeFixedSized
{-# INLINE decodeCertVRF #-}
{-# DEPRECATED decodeCertVRF "Use `decodeFixedSized` instead" #-}

data CertifiedVRF v a = CertifiedVRF
  { certifiedOutput :: !(OutputVRF v)
  , certifiedProof :: !(CertVRF v)
  }
  deriving (Generic)

deriving instance VRFAlgorithm v => Eq (CertifiedVRF v a)
deriving instance VRFAlgorithm v => Ord (CertifiedVRF v a)
deriving instance VRFAlgorithm v => Show (CertifiedVRF v a)

instance VRFAlgorithm v => NoThunks (CertifiedVRF v a)

-- use generic instance

instance (VRFAlgorithm v, Typeable a) => ToCBOR (CertifiedVRF v a) where
  toCBOR cvrf =
    encodeListLen 2
      <> toCBOR (certifiedOutput cvrf)
      <> encodeFixedSized (certifiedProof cvrf)

  encodedSizeExpr _size proxy =
    1
      + certifiedOutputSize (certifiedOutput <$> proxy)
      + fromIntegral @Word @Size (fixedSize (Proxy @(CertVRF v)))
    where
      certifiedOutputSize :: Proxy (OutputVRF v) -> Size
      certifiedOutputSize _proxy =
        fromIntegral @Word @Size (sizeOutputVRF (Proxy :: Proxy v))

instance (VRFAlgorithm v, Typeable a) => FromCBOR (CertifiedVRF v a) where
  fromCBOR =
    CertifiedVRF
      <$ enforceSize "CertifiedVRF" 2
      <*> fromCBOR
      <*> decodeFixedSized
  {-# INLINE fromCBOR #-}

evalCertified ::
  (VRFAlgorithm v, Signable v a) =>
  ContextVRF v ->
  a ->
  SignKeyVRF v ->
  CertifiedVRF v a
evalCertified ctxt a key = uncurry CertifiedVRF $ evalVRF ctxt a key

verifyCertified ::
  (VRFAlgorithm v, Signable v a) =>
  ContextVRF v ->
  VerKeyVRF v ->
  a ->
  CertifiedVRF v a ->
  Bool
verifyCertified ctxt vk a CertifiedVRF {certifiedOutput, certifiedProof} =
  case verifyVRF ctxt vk a certifiedProof of
    Nothing -> False
    Just output -> output == certifiedOutput

--
-- 'Size' expressions for 'ToCBOR' instances
--

encodedVerKeyVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (VerKeyVRF v) -> Size
encodedVerKeyVRFSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size (withWordSize (fixedSize (Proxy @(VerKeyVRF v))))
    -- payload
    + fromIntegral @Word @Size (fixedSize (Proxy @(VerKeyVRF v)))

encodedSignKeyVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (SignKeyVRF v) -> Size
encodedSignKeyVRFSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size (withWordSize (fixedSize (Proxy @(SignKeyVRF v))))
    -- payload
    + fromIntegral @Word @Size (fixedSize (Proxy @(SignKeyVRF v)))

encodedCertVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (CertVRF v) -> Size
encodedCertVRFSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size (withWordSize (fixedSize (Proxy @(CertVRF v))))
    -- payload
    + fromIntegral @Word @Size (fixedSize (Proxy @(CertVRF v)))
