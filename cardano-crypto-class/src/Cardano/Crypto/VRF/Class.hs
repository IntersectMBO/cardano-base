{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Abstract Verifiable Random Functions.
module Cardano.Crypto.VRF.Class
  (
    -- * VRF algorithm class
    VRFAlgorithm (..)

    -- * 'CertifiedVRF' wrapper
  , CertifiedVRF (..)
  , evalCertified
  , verifyCertified

    -- * CBOR encoding and decoding
  , encodeVerKeyVRF
  , decodeVerKeyVRF
  , encodeSignKeyVRF
  , decodeSignKeyVRF
  , encodeCertVRF
  , decodeCertVRF


    -- * Encoded 'Size' expressions
  , encodedVerKeyVRFSizeExpr
  , encodedSignKeyVRFSizeExpr
  , encodedCertVRFSizeExpr
)
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Kind (Type)
import Data.Proxy (Proxy(..))
import Data.Typeable (Typeable)
import GHC.Exts (Constraint)
import GHC.Generics (Generic)
import GHC.Stack

import Cardano.Prelude (NoUnexpectedThunks)
import Cardano.Binary
         (Decoder, Encoding, FromCBOR (..), ToCBOR (..), Size,
          encodeListLen, enforceSize, decodeBytes, encodeBytes,
          withWordSize)

import Crypto.Random (MonadRandom)

import Cardano.Crypto.Util (Empty)
import Cardano.Crypto.Seed (Seed)
import Cardano.Crypto.Hash.Class (HashAlgorithm, Hash, hashRaw)

type OutputVRF = ByteString

class ( Typeable v
      , Show (VerKeyVRF v)
      , Eq (VerKeyVRF v)
      , Show (SignKeyVRF v)
      , Show (CertVRF v)
      , Eq (CertVRF v)
      , NoUnexpectedThunks (CertVRF    v)
      , NoUnexpectedThunks (VerKeyVRF  v)
      , NoUnexpectedThunks (SignKeyVRF v)
      )
      => VRFAlgorithm v where


  --
  -- Key and signature types
  --

  data VerKeyVRF  v :: Type
  data SignKeyVRF v :: Type
  data CertVRF    v :: Type


  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF :: proxy v -> String

  deriveVerKeyVRF :: SignKeyVRF v -> VerKeyVRF v

  hashVerKeyVRF :: HashAlgorithm h => VerKeyVRF v -> Hash h (VerKeyVRF v)
  hashVerKeyVRF = hashRaw rawSerialiseVerKeyVRF

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

  evalVRF
    :: (MonadRandom m, HasCallStack, Signable v a)
    => ContextVRF v
    -> a
    -> SignKeyVRF v
    -> m (OutputVRF, CertVRF v)

  verifyVRF
    :: (HasCallStack, Signable v a)
    => ContextVRF v
    -> VerKeyVRF v
    -> a
    -> (OutputVRF, CertVRF v)
    -> Bool

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

  sizeVerKeyVRF  :: proxy v -> Word
  sizeSignKeyVRF :: proxy v -> Word
  sizeCertVRF    :: proxy v -> Word
  sizeOutputVRF  :: proxy v -> Word

  rawSerialiseVerKeyVRF    :: VerKeyVRF  v -> ByteString
  rawSerialiseSignKeyVRF   :: SignKeyVRF v -> ByteString
  rawSerialiseCertVRF      :: CertVRF    v -> ByteString

  rawDeserialiseVerKeyVRF  :: ByteString -> Maybe (VerKeyVRF  v)
  rawDeserialiseSignKeyVRF :: ByteString -> Maybe (SignKeyVRF v)
  rawDeserialiseCertVRF    :: ByteString -> Maybe (CertVRF    v)

  {-# MINIMAL
        algorithmNameVRF
      , deriveVerKeyVRF
      , evalVRF
      , verifyVRF
      , seedSizeVRF
      , (genKeyVRF                | genKeyPairVRF)
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
        | actual /= expected
                    -> fail ("decodeVerKeyVRF: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeVerKeyVRF: cannot decode key"
        where
          expected = fromIntegral (sizeVerKeyVRF (Proxy :: Proxy v))
          actual   = BS.length bs

decodeSignKeyVRF :: forall v s. VRFAlgorithm v => Decoder s (SignKeyVRF v)
decodeSignKeyVRF = do
    bs <- decodeBytes
    case rawDeserialiseSignKeyVRF bs of
      Just sk -> return sk
      Nothing
        | actual /= expected
                    -> fail ("decodeSignKeyVRF: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeSignKeyVRF: cannot decode key"
        where
          expected = fromIntegral (sizeSignKeyVRF (Proxy :: Proxy v))
          actual   = BS.length bs

decodeCertVRF :: forall v s. VRFAlgorithm v => Decoder s (CertVRF v)
decodeCertVRF = do
    bs <- decodeBytes
    case rawDeserialiseCertVRF bs of
      Just crt -> return crt
      Nothing
        | actual /= expected
                    -> fail ("decodeCertVRF: wrong length, expected " ++
                             show expected ++ " bytes but got " ++ show actual)
        | otherwise -> fail "decodeCertVRF: cannot decode key"
        where
          expected = fromIntegral (sizeCertVRF (Proxy :: Proxy v))
          actual   = BS.length bs

data CertifiedVRF v a
  = CertifiedVRF
      { certifiedOutput :: !OutputVRF
      , certifiedProof :: !(CertVRF v)
      }
  deriving Generic

deriving instance VRFAlgorithm v => Show (CertifiedVRF v a)
deriving instance VRFAlgorithm v => Eq   (CertifiedVRF v a)

instance VRFAlgorithm v => NoUnexpectedThunks (CertifiedVRF v a)
  -- use generic instance

instance (VRFAlgorithm v, Typeable a) => ToCBOR (CertifiedVRF v a) where
  toCBOR cvrf =
    encodeListLen 2 <>
      toCBOR (certifiedOutput cvrf) <>
      encodeCertVRF (certifiedProof cvrf)

  encodedSizeExpr _size proxy =
        1
      + certifiedOutputSize (certifiedOutput <$> proxy)
      + fromIntegral (sizeCertVRF (Proxy :: Proxy v))
    where
      certifiedOutputSize :: Proxy OutputVRF -> Size
      certifiedOutputSize _proxy =
        fromIntegral $ sizeOutputVRF (Proxy :: Proxy v)

instance (VRFAlgorithm v, Typeable a) => FromCBOR (CertifiedVRF v a) where
  fromCBOR =
    CertifiedVRF <$
      enforceSize "CertifiedVRF" 2 <*>
      fromCBOR <*>
      decodeCertVRF

evalCertified
  :: (VRFAlgorithm v, MonadRandom m, Signable v a)
  => ContextVRF v
  -> a
  -> SignKeyVRF v
  -> m (CertifiedVRF v a)
evalCertified ctxt a key = uncurry CertifiedVRF <$> evalVRF ctxt a key

verifyCertified
  :: (VRFAlgorithm v, Signable v a)
  => ContextVRF v
  -> VerKeyVRF v
  -> a
  -> CertifiedVRF v a
  -> Bool
verifyCertified ctxt vk a CertifiedVRF {..} = verifyVRF ctxt vk a (certifiedOutput, certifiedProof)

--
-- 'Size' expressions for 'ToCBOR' instances
--

-- | 'Size' expression for 'VerKeyVRF' which is using 'sizeVerKeyVRF' encoded as
-- 'Size'.
--
encodedVerKeyVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (VerKeyVRF v) -> Size
encodedVerKeyVRFSizeExpr _proxy =
      -- 'encodeBytes' envelope
      fromIntegral ((withWordSize :: Word -> Integer) (sizeVerKeyVRF (Proxy :: Proxy v)))
      -- payload
    + fromIntegral (sizeVerKeyVRF (Proxy :: Proxy v))

-- | 'Size' expression for 'SignKeyVRF' which is using 'sizeSignKeyVRF' encoded
-- as 'Size'
--
encodedSignKeyVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (SignKeyVRF v) -> Size
encodedSignKeyVRFSizeExpr _proxy =
      -- 'encodeBytes' envelope
      fromIntegral ((withWordSize :: Word -> Integer) (sizeSignKeyVRF (Proxy :: Proxy v)))
      -- payload
    + fromIntegral (sizeSignKeyVRF (Proxy :: Proxy v))

-- | 'Size' expression for 'CertVRF' which is using 'sizeCertVRF' encoded as
-- 'Size'.
--
encodedCertVRFSizeExpr :: forall v. VRFAlgorithm v => Proxy (CertVRF v) -> Size
encodedCertVRFSizeExpr _proxy =
      -- 'encodeBytes' envelope
      fromIntegral ((withWordSize :: Word -> Integer) (sizeCertVRF (Proxy :: Proxy v)))
      -- payload
    + fromIntegral (sizeCertVRF (Proxy :: Proxy v))
