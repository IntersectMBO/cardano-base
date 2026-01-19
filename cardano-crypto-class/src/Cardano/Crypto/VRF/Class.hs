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
  decodeBytes,
  encodeBytes,
  encodeListLen,
  enforceSize,
  withWordSize,
 )
import Cardano.Crypto.Hash.Class (Hash, HashAlgorithm, hashWith)
import Cardano.Crypto.Seed (Seed)
import Cardano.Crypto.Util (Empty, byteArrayToNatural, naturalToByteArray)
import Control.DeepSeq (NFData)
import Data.Array.Byte (ByteArray)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Short as SBS (fromShort)
import Data.Kind (Type)
import Data.MemPack.Buffer (byteArrayToShortByteString)
import Data.Proxy (Proxy (..))
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack
import GHC.TypeLits (ErrorMessage (..), TypeError)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))
import Numeric.Natural (Natural)

class
  ( Typeable v
  , Show (VerKeyVRF v)
  , Eq (VerKeyVRF v)
  , Show (SignKeyVRF v)
  , Show (CertVRF v)
  , Eq (CertVRF v)
  , NoThunks (CertVRF v)
  , NoThunks (VerKeyVRF v)
  , NoThunks (SignKeyVRF v)
  ) =>
  VRFAlgorithm v
  where
  --
  -- Key and signature types
  --

  data VerKeyVRF v :: Type
  data SignKeyVRF v :: Type
  data CertVRF v :: Type

  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF :: proxy v -> String

  deriveVerKeyVRF :: SignKeyVRF v -> VerKeyVRF v

  hashVerKeyVRF :: HashAlgorithm h => VerKeyVRF v -> Hash h (VerKeyVRF v)
  hashVerKeyVRF = hashWith rawSerialiseVerKeyVRF

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

  sizeVerKeyVRF :: proxy v -> Word
  sizeSignKeyVRF :: proxy v -> Word
  sizeCertVRF :: proxy v -> Word
  sizeOutputVRF :: proxy v -> Word

  rawSerialiseVerKeyVRF :: VerKeyVRF v -> ByteString
  rawSerialiseSignKeyVRF :: SignKeyVRF v -> ByteString
  rawSerialiseCertVRF :: CertVRF v -> ByteString

  rawDeserialiseVerKeyVRF :: ByteString -> Maybe (VerKeyVRF v)
  rawDeserialiseSignKeyVRF :: ByteString -> Maybe (SignKeyVRF v)
  rawDeserialiseCertVRF :: ByteString -> Maybe (CertVRF v)

  {-# MINIMAL
    algorithmNameVRF
    , deriveVerKeyVRF
    , evalVRF
    , verifyVRF
    , seedSizeVRF
    , (genKeyVRF | genKeyPairVRF)
    , rawSerialiseVerKeyVRF
    , rawSerialiseSignKeyVRF
    , rawSerialiseCertVRF
    , rawDeserialiseVerKeyVRF
    , rawDeserialiseSignKeyVRF
    , rawDeserialiseCertVRF
    , sizeVerKeyVRF
    , sizeSignKeyVRF
    , sizeCertVRF
    , sizeOutputVRF
    #-}

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
encodeVerKeyVRF = encodeBytes . rawSerialiseVerKeyVRF

encodeSignKeyVRF :: VRFAlgorithm v => SignKeyVRF v -> Encoding
encodeSignKeyVRF = encodeBytes . rawSerialiseSignKeyVRF

encodeCertVRF :: VRFAlgorithm v => CertVRF v -> Encoding
encodeCertVRF = encodeBytes . rawSerialiseCertVRF

decodeVerKeyVRF :: forall v s. VRFAlgorithm v => Decoder s (VerKeyVRF v)
decodeVerKeyVRF = do
  bs <- decodeBytes
  case rawDeserialiseVerKeyVRF bs of
    Just vk -> return vk
    Nothing
      | actual /= expected ->
          fail
            ( "decodeVerKeyVRF: wrong length, expected "
                ++ show expected
                ++ " bytes but got "
                ++ show actual
            )
      | otherwise -> fail "decodeVerKeyVRF: cannot decode key"
      where
        expected = fromIntegral @Word @Int (sizeVerKeyVRF (Proxy :: Proxy v))
        actual = BS.length bs
{-# INLINEABLE decodeVerKeyVRF #-}

decodeSignKeyVRF :: forall v s. VRFAlgorithm v => Decoder s (SignKeyVRF v)
decodeSignKeyVRF = do
  bs <- decodeBytes
  case rawDeserialiseSignKeyVRF bs of
    Just sk -> return sk
    Nothing
      | actual /= expected ->
          fail
            ( "decodeSignKeyVRF: wrong length, expected "
                ++ show expected
                ++ " bytes but got "
                ++ show actual
            )
      | otherwise -> fail "decodeSignKeyVRF: cannot decode key"
      where
        expected = fromIntegral @Word @Int (sizeSignKeyVRF (Proxy :: Proxy v))
        actual = BS.length bs

decodeCertVRF :: forall v s. VRFAlgorithm v => Decoder s (CertVRF v)
decodeCertVRF = do
  bs <- decodeBytes
  case rawDeserialiseCertVRF bs of
    Just crt -> return crt
    Nothing
      | actual /= expected ->
          fail
            ( "decodeCertVRF: wrong length, expected "
                ++ show expected
                ++ " bytes but got "
                ++ show actual
            )
      | otherwise -> fail "decodeCertVRF: cannot decode key"
      where
        expected = fromIntegral @Word @Int (sizeCertVRF (Proxy :: Proxy v))
        actual = BS.length bs
{-# INLINEABLE decodeCertVRF #-}

data CertifiedVRF v a = CertifiedVRF
  { certifiedOutput :: !(OutputVRF v)
  , certifiedProof :: !(CertVRF v)
  }
  deriving (Generic)

deriving instance VRFAlgorithm v => Show (CertifiedVRF v a)
deriving instance VRFAlgorithm v => Eq (CertifiedVRF v a)

instance VRFAlgorithm v => NoThunks (CertifiedVRF v a)

-- use generic instance

instance (VRFAlgorithm v, Typeable a) => ToCBOR (CertifiedVRF v a) where
  toCBOR cvrf =
    encodeListLen 2
      <> toCBOR (certifiedOutput cvrf)
      <> encodeCertVRF (certifiedProof cvrf)

  encodedSizeExpr _size proxy =
    1
      + certifiedOutputSize (certifiedOutput <$> proxy)
      + fromIntegral @Word @Size (sizeCertVRF (Proxy :: Proxy v))
    where
      certifiedOutputSize :: Proxy (OutputVRF v) -> Size
      certifiedOutputSize _proxy =
        fromIntegral @Word @Size (sizeOutputVRF (Proxy :: Proxy v))

instance (VRFAlgorithm v, Typeable a) => FromCBOR (CertifiedVRF v a) where
  fromCBOR =
    CertifiedVRF
      <$ enforceSize "CertifiedVRF" 2
      <*> fromCBOR
      <*> decodeCertVRF
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

-- | 'Size' expression for 'VerKeyVRF' which is using 'sizeVerKeyVRF' encoded as
-- 'Size'.
encodedVerKeyVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (VerKeyVRF v) -> Size
encodedVerKeyVRFSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size ((withWordSize :: Word -> Integer) (sizeVerKeyVRF (Proxy :: Proxy v)))
    -- payload
    + fromIntegral @Word @Size (sizeVerKeyVRF (Proxy :: Proxy v))

-- | 'Size' expression for 'SignKeyVRF' which is using 'sizeSignKeyVRF' encoded
-- as 'Size'
encodedSignKeyVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (SignKeyVRF v) -> Size
encodedSignKeyVRFSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size ((withWordSize :: Word -> Integer) (sizeSignKeyVRF (Proxy :: Proxy v)))
    -- payload
    + fromIntegral @Word @Size (sizeSignKeyVRF (Proxy :: Proxy v))

-- | 'Size' expression for 'CertVRF' which is using 'sizeCertVRF' encoded as
-- 'Size'.
encodedCertVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (CertVRF v) -> Size
encodedCertVRFSizeExpr _proxy =
  -- 'encodeBytes' envelope
  fromIntegral @Integer @Size ((withWordSize :: Word -> Integer) (sizeCertVRF (Proxy :: Proxy v)))
    -- payload
    + fromIntegral @Word @Size (sizeCertVRF (Proxy :: Proxy v))
