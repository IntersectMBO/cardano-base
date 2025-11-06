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

-- | BLS12-381 digital signatures (minimal signature size variant).
module Cardano.Crypto.DSIGN.BLS12381MinSig (
  BLS12381MinSigDSIGN,
) where

import Cardano.Binary (FromCBOR (..), ToCBOR (..))
import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Seed (getSeedBytes)
import Cardano.Crypto.Util (SignableRepresentation, getSignableRepresentation)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS

-- | Algorithm marker for BLS12-381 Minimal-signature-size:
-- public keys on G2 (96B), signatures on G1 (48B), secret key 32B.
data BLS12381MinSigDSIGN

defaultDst :: ByteString
defaultDst = "BLS_DST_CARDANO_BASE_V1"

instance DSIGNAlgorithm BLS12381MinSigDSIGN where
  type SeedSizeDSIGN BLS12381MinSigDSIGN = 32
  type SizeVerKeyDSIGN BLS12381MinSigDSIGN = 96 -- G2 compressed
  type SizeSignKeyDSIGN BLS12381MinSigDSIGN = 32 -- scalar
  type SizeSigDSIGN BLS12381MinSigDSIGN = 48 -- G1 compressed

  type Signable BLS12381MinSigDSIGN = SignableRepresentation
  type ContextDSIGN BLS12381MinSigDSIGN = (Maybe ByteString, Maybe ByteString)

  newtype VerKeyDSIGN BLS12381MinSigDSIGN = VerKeyBLSMinSig (BLS.PublicKey BLS.Curve2)
    deriving stock (Generic)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "VerKeyDSIGN BLS12381MinSigDSIGN"
            (VerKeyDSIGN BLS12381MinSigDSIGN)
  newtype SignKeyDSIGN BLS12381MinSigDSIGN = SignKeyBLSMinSig BLS.SecretKey
    deriving stock (Generic)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SignKeyDSIGN BLS12381MinSigDSIGN"
            (SignKeyDSIGN BLS12381MinSigDSIGN)
  newtype SigDSIGN BLS12381MinSigDSIGN = SigBLSMinSig (BLS.Signature BLS.Curve2)
    deriving stock (Generic)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SigDSIGN BLS12381MinSigDSIGN"
            (SigDSIGN BLS12381MinSigDSIGN)

  algorithmNameDSIGN _ = "bls12-381-minsig"

  rawSerialiseVerKeyDSIGN (VerKeyBLSMinSig pk) = BLS.publicKeyToCompressedBS pk
  rawSerialiseSignKeyDSIGN (SignKeyBLSMinSig sk) = BLS.secretKeyToBS sk
  rawSerialiseSigDSIGN (SigBLSMinSig sig) = BLS.signatureToCompressedBS @BLS.Curve2 sig

  rawDeserialiseVerKeyDSIGN bs =
    VerKeyBLSMinSig <$> either (const Nothing) Just (BLS.publicKeyFromCompressedBS @BLS.Curve2 bs)

  rawDeserialiseSignKeyDSIGN bs =
    SignKeyBLSMinSig <$> either (const Nothing) Just (BLS.secretKeyFromBS bs)

  rawDeserialiseSigDSIGN bs =
    SigBLSMinSig <$> either (const Nothing) Just (BLS.signatureFromCompressedBS @BLS.Curve2 bs)

  deriveVerKeyDSIGN (SignKeyBLSMinSig sk) = VerKeyBLSMinSig (BLS.blsSkToPk @BLS.Curve2 sk)

  signDSIGN (mdst, maug) a (SignKeyBLSMinSig sk) =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
     in SigBLSMinSig (BLS.blsSign @BLS.Curve2 Proxy sk msg effDst effAug)

  verifyDSIGN (mdst, maug) (VerKeyBLSMinSig vk) a (SigBLSMinSig sig) =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
     in if BLS.blsSignatureVerify @BLS.Curve2 vk msg sig effDst effAug
          then Right ()
          else Left "verifyDSIGN (BLS minsig): verification failed"

  genKeyDSIGN seed =
    case BLS.blsKeyGen (getSeedBytes seed) Nothing of
      Left _ -> error "genKeyDSIGN (BLS minsig): invalid seed (needs >=32 bytes)"
      Right sk -> SignKeyBLSMinSig sk

instance ToCBOR (VerKeyDSIGN BLS12381MinSigDSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN BLS12381MinSigDSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN BLS12381MinSigDSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN BLS12381MinSigDSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN BLS12381MinSigDSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN BLS12381MinSigDSIGN) where
  fromCBOR = decodeSigDSIGN

instance Eq (VerKeyDSIGN BLS12381MinSigDSIGN) where
  VerKeyBLSMinSig a == VerKeyBLSMinSig b =
    BLS.publicKeyToCompressedBS a == BLS.publicKeyToCompressedBS b

instance Eq (SignKeyDSIGN BLS12381MinSigDSIGN) where
  SignKeyBLSMinSig a == SignKeyBLSMinSig b =
    BLS.secretKeyToBS a == BLS.secretKeyToBS b

instance Eq (SigDSIGN BLS12381MinSigDSIGN) where
  SigBLSMinSig a == SigBLSMinSig b =
    BLS.signatureToCompressedBS @BLS.Curve2 a == BLS.signatureToCompressedBS @BLS.Curve2 b

instance Show (VerKeyDSIGN BLS12381MinSigDSIGN) where
  show (VerKeyBLSMinSig vk) =
    "VerKeyBLSMinSig " <> show (BLS.publicKeyToCompressedBS vk)

instance Show (SignKeyDSIGN BLS12381MinSigDSIGN) where
  show (SignKeyBLSMinSig sk) =
    "SignKeyBLSMinSig " <> show (BLS.secretKeyToBS sk)

instance Show (SigDSIGN BLS12381MinSigDSIGN) where
  show (SigBLSMinSig sig) =
    "SigBLSMinSig " <> show (BLS.signatureToCompressedBS @BLS.Curve2 sig)
