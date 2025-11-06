{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | BLS12-381 digital signatures (minimal public key size variant).
module Cardano.Crypto.DSIGN.BLS12381MinPk (
  BLS12381MinPkDSIGN,
) where

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Seed (getSeedBytes)
import Cardano.Crypto.Util (SignableRepresentation, getSignableRepresentation)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)

import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)

-- Our internal BLS implementation
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS

-- | Algorithm marker for BLS12-381 Minimal-PK-size:
-- public keys on G1 (48B), signatures on G2 (96B), secret key 32B.
data BLS12381MinPkDSIGN

defaultDst :: ByteString
defaultDst = "BLS_DST_CARDANO_BASE_V1"

instance DSIGNAlgorithm BLS12381MinPkDSIGN where
  -- DSIGN associated sizes (in bytes)
  type SeedSizeDSIGN BLS12381MinPkDSIGN = 32
  type SizeVerKeyDSIGN BLS12381MinPkDSIGN = 48 -- G1 compressed
  type SizeSignKeyDSIGN BLS12381MinPkDSIGN = 32 -- scalar
  type SizeSigDSIGN BLS12381MinPkDSIGN = 96 -- G2 compressed

  -- What messages are signable by this DSIGN
  type Signable BLS12381MinPkDSIGN = SignableRepresentation
  type ContextDSIGN BLS12381MinPkDSIGN = (Maybe ByteString, Maybe ByteString)

  -- Concrete DSIGN key/sig representations
  newtype VerKeyDSIGN BLS12381MinPkDSIGN = VerKeyBLSMinPk (BLS.PublicKey BLS.Curve1)
    deriving stock (Generic)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "VerKeyDSIGN BLS12381MinPkDSIGN"
            (VerKeyDSIGN BLS12381MinPkDSIGN)
  newtype SignKeyDSIGN BLS12381MinPkDSIGN = SignKeyBLSMinPk BLS.SecretKey
    deriving stock (Generic)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SignKeyDSIGN BLS12381MinPkDSIGN"
            (SignKeyDSIGN BLS12381MinPkDSIGN)
  newtype SigDSIGN BLS12381MinPkDSIGN = SigBLSMinPk (BLS.Signature BLS.Curve1)
    deriving stock (Generic)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SigDSIGN BLS12381MinPkDSIGN"
            (SigDSIGN BLS12381MinPkDSIGN)

  -- Note: BLS.Signature Curve1 lives on Dual Curve1 == Curve2 (G2), as intended.
  algorithmNameDSIGN _ = "bls12-381-minpk"

  -- Raw serialization (canonical encodings, exact sizes)
  rawSerialiseVerKeyDSIGN (VerKeyBLSMinPk pk) = BLS.publicKeyToCompressedBS pk
  rawSerialiseSignKeyDSIGN (SignKeyBLSMinPk sk) = BLS.secretKeyToBS sk
  rawSerialiseSigDSIGN (SigBLSMinPk sg) = BLS.signatureToCompressedBS @BLS.Curve1 sg

  rawDeserialiseVerKeyDSIGN bs =
    VerKeyBLSMinPk <$> either (const Nothing) Just (BLS.publicKeyFromCompressedBS @BLS.Curve1 bs)

  rawDeserialiseSignKeyDSIGN bs =
    SignKeyBLSMinPk <$> either (const Nothing) Just (BLS.secretKeyFromBS bs)

  rawDeserialiseSigDSIGN bs =
    SigBLSMinPk <$> either (const Nothing) Just (BLS.signatureFromCompressedBS @BLS.Curve1 bs)

  deriveVerKeyDSIGN (SignKeyBLSMinPk sk) = VerKeyBLSMinPk (BLS.blsSkToPk @BLS.Curve1 sk)

  signDSIGN (mdst, maug) a (SignKeyBLSMinPk sk) =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
     in SigBLSMinPk (BLS.blsSign @BLS.Curve1 Proxy sk msg effDst effAug)

  verifyDSIGN (mdst, maug) (VerKeyBLSMinPk vk) a (SigBLSMinPk sig) =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
     in if BLS.blsSignatureVerify @BLS.Curve1 vk msg sig effDst effAug
          then Right ()
          else Left "verifyDSIGN (BLS minpk): verification failed"

  genKeyDSIGN seed =
    case BLS.blsKeyGen (getSeedBytes seed) Nothing of
      Left _ -> error "genKeyDSIGN (BLS minpk): invalid seed (needs >=32 bytes)"
      Right sk -> SignKeyBLSMinPk sk

-- CBOR instances (delegating to the shared helpers; includes size checks)
instance ToCBOR (VerKeyDSIGN BLS12381MinPkDSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN BLS12381MinPkDSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN BLS12381MinPkDSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN BLS12381MinPkDSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN BLS12381MinPkDSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN BLS12381MinPkDSIGN) where
  fromCBOR = decodeSigDSIGN

-- Eq via canonical encodings
instance Eq (VerKeyDSIGN BLS12381MinPkDSIGN) where
  VerKeyBLSMinPk a == VerKeyBLSMinPk b =
    BLS.publicKeyToCompressedBS a == BLS.publicKeyToCompressedBS b

instance Eq (SignKeyDSIGN BLS12381MinPkDSIGN) where
  SignKeyBLSMinPk a == SignKeyBLSMinPk b =
    BLS.secretKeyToBS a == BLS.secretKeyToBS b

instance Eq (SigDSIGN BLS12381MinPkDSIGN) where
  SigBLSMinPk a == SigBLSMinPk b =
    BLS.signatureToCompressedBS @BLS.Curve1 a == BLS.signatureToCompressedBS @BLS.Curve1 b

-- Show via canonical encodings (ByteString's Show instance)
instance Show (VerKeyDSIGN BLS12381MinPkDSIGN) where
  show (VerKeyBLSMinPk vk) =
    "VerKeyBLSMinPk " <> show (BLS.publicKeyToCompressedBS vk)

instance Show (SignKeyDSIGN BLS12381MinPkDSIGN) where
  show (SignKeyBLSMinPk sk) =
    "SignKeyBLSMinPk " <> show (BLS.secretKeyToBS sk)

instance Show (SigDSIGN BLS12381MinPkDSIGN) where
  show (SigBLSMinPk sg) =
    "SigBLSMinPk " <> show (BLS.signatureToCompressedBS @BLS.Curve1 sg)

-- NoThunks: handled via the deriving clauses above (we only check WHNF for these FFI-backed values).
