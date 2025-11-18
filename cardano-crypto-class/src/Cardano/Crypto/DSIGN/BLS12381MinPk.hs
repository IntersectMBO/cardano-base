{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | BLS12-381 digital signatures (minimal public key size variant).
module Cardano.Crypto.DSIGN.BLS12381MinPk (
  BLS12381MinPkDSIGN,
  PopDSIGN (..),
  derivePopDSIGN,
  verifyPopDSIGN,
  rawSerialisePopBLS,
  rawDeserialisePopBLS,
  popByteLength,
) where

import Cardano.Binary (FromCBOR (..), Size, ToCBOR (..), decodeBytes, encodeBytes, withWordSize)
import Cardano.Crypto.DSIGN.Class (
  DSIGNAlgorithm (..),
  failSizeCheck,
  decodeSigDSIGN,
  decodeSignKeyDSIGN,
  decodeVerKeyDSIGN,
  encodeSigDSIGN,
  encodeSignKeyDSIGN,
  encodeVerKeyDSIGN,
  encodedSigDSIGNSizeExpr,
  encodedSignKeyDSIGNSizeExpr,
  encodedVerKeyDSIGNSizeExpr,
 )
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbFromByteStringCheck,
  psbToByteString,
 )
import Cardano.Crypto.Seed (getSeedBytes)
import Cardano.Crypto.Util (SignableRepresentation, getSignableRepresentation)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import GHC.TypeLits (KnownNat, Nat)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)

-- Our internal BLS implementation
import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS

-- | Algorithm marker for BLS12-381 Minimal-PK-size:
-- public keys on G1 (48B), signatures on G2 (96B), secret key 32B.
data BLS12381MinPkDSIGN

defaultDst :: ByteString
defaultDst = "BLS_DST_CARDANO_BASE_V1"

type BlsSecretKeyBytes = 32 :: Nat
type BlsMinPkVerKeyBytes = 48 :: Nat
type BlsMinPkSigBytes = 96 :: Nat
type BlsMinPkPopBytes = 192 :: Nat

newtype PopDSIGN
  = PopDSIGN (PinnedSizedBytes BlsMinPkPopBytes)
  deriving stock (Generic)
  deriving newtype (Eq, Show)
  deriving
    (NoThunks)
    via OnlyCheckWhnfNamed "PopDSIGN" PopDSIGN

rawSerialisePopBLS ::
  PopDSIGN ->
  ByteString
rawSerialisePopBLS (PopDSIGN psb) =
  psbToByteString psb

rawDeserialisePopBLS ::
  ByteString ->
  Maybe PopDSIGN
rawDeserialisePopBLS bs
  | Just _ <- validatePopBytes bs =
      PopDSIGN <$> psbFromByteStringCheck bs
  | otherwise = Nothing

popByteLength :: Int
popByteLength =
  2 * compressedPopElementLength

compressedPopElementLength :: Int
compressedPopElementLength =
  BLS.compressedSizePoint (Proxy @(BLS.Dual BLS.Curve1))

serializePopProof ::
  BLS.ProofOfPossession BLS.Curve1 ->
  ByteString
serializePopProof (BLS.ProofOfPossession mu1 mu2) =
  BLS.blsCompress mu1 <> BLS.blsCompress mu2

validatePopBytes ::
  ByteString ->
  Maybe (BLS.ProofOfPossession BLS.Curve1)
validatePopBytes bs
  | BS.length bs /= popByteLength = Nothing
  | otherwise = do
      let (mu1Bytes, mu2Bytes) = BS.splitAt compressedPopElementLength bs
      mu1 <- decodeMu1 mu1Bytes
      mu2 <- decodeMu2 mu2Bytes
      pure (BLS.ProofOfPossession mu1 mu2)
  where
    decodeMu1 bytes =
      case BLS.blsUncompress @(BLS.Dual BLS.Curve1) bytes of
        Right point
          | BLS.blsIsInf point -> Nothing
          | otherwise -> Just point
        Left _ -> Nothing
    decodeMu2 bytes =
      case BLS.blsUncompress @(BLS.Dual BLS.Curve1) bytes of
        Right point
          | BLS.blsIsInf point -> Nothing
          | otherwise -> Just point
        Left _ -> Nothing

encodedPopDSIGNSizeExpr :: Proxy PopDSIGN -> Size
encodedPopDSIGNSizeExpr _ =
  -- encodeBytes envelope
  fromIntegral ((withWordSize :: Word -> Integer) (fromIntegral popByteLength))
    -- payload
    + fromIntegral popByteLength

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
  newtype VerKeyDSIGN BLS12381MinPkDSIGN
    = VerKeyBLSMinPk (PinnedSizedBytes BlsMinPkVerKeyBytes)
    deriving stock (Generic)
    deriving newtype (Eq, Show)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "VerKeyDSIGN BLS12381MinPkDSIGN"
            (VerKeyDSIGN BLS12381MinPkDSIGN)
  newtype SignKeyDSIGN BLS12381MinPkDSIGN
    = SignKeyBLSMinPk (PinnedSizedBytes BlsSecretKeyBytes)
    deriving stock (Generic)
    deriving newtype (Eq, Show)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SignKeyDSIGN BLS12381MinPkDSIGN"
            (SignKeyDSIGN BLS12381MinPkDSIGN)
  newtype SigDSIGN BLS12381MinPkDSIGN
    = SigBLSMinPk (PinnedSizedBytes BlsMinPkSigBytes)
    deriving stock (Generic)
    deriving newtype (Eq, Show)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SigDSIGN BLS12381MinPkDSIGN"
            (SigDSIGN BLS12381MinPkDSIGN)

  algorithmNameDSIGN _ = "bls12-381-minpk"

  rawSerialiseVerKeyDSIGN (VerKeyBLSMinPk vk) = psbToByteString vk
  rawSerialiseSignKeyDSIGN (SignKeyBLSMinPk sk) = psbToByteString sk
  rawSerialiseSigDSIGN (SigBLSMinPk sig) = psbToByteString sig

  rawDeserialiseVerKeyDSIGN bs = do
    _ <- either (const Nothing) Just (BLS.publicKeyFromCompressedBS @BLS.Curve1 bs)
    VerKeyBLSMinPk <$> psbFromByteStringCheck bs

  rawDeserialiseSignKeyDSIGN bs =
    SignKeyBLSMinPk <$> psbFromByteStringCheck bs

  rawDeserialiseSigDSIGN bs = do
    _ <- either (const Nothing) Just (BLS.signatureFromCompressedBS @BLS.Curve1 bs)
    SigBLSMinPk <$> psbFromByteStringCheck bs

  deriveVerKeyDSIGN sk =
    let blsSk = expectSecretKey "deriveVerKeyDSIGN" sk
        vk = BLS.blsSkToPk @BLS.Curve1 blsSk
     in VerKeyBLSMinPk (bytesToPinned "deriveVerKeyDSIGN" (BLS.publicKeyToCompressedBS vk))

  signDSIGN (mdst, maug) a skBytes =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
        blsSk = expectSecretKey "signDSIGN" skBytes
        sig = BLS.blsSign @BLS.Curve1 Proxy blsSk msg effDst effAug
     in SigBLSMinPk (bytesToPinned "signDSIGN" (BLS.signatureToCompressedBS @BLS.Curve1 sig))

  verifyDSIGN (mdst, maug) vkBytes a sigBytes =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
     in case ( decodeVerKeyBytes vkBytes
             , decodeSignatureBytes sigBytes
             ) of
          (Right vk, Right sig) ->
            if BLS.blsSignatureVerify @BLS.Curve1 vk msg sig effDst effAug
              then Right ()
              else Left "verifyDSIGN (BLS minpk): verification failed"
          (Left _, _) -> Left "verifyDSIGN (BLS minpk): invalid verification key"
          (_, Left _) -> Left "verifyDSIGN (BLS minpk): invalid signature"

  genKeyDSIGN seed =
    case BLS.blsKeyGen (getSeedBytes seed) Nothing of
      Left _ -> error "genKeyDSIGN (BLS minpk): invalid seed (needs >=32 bytes)"
      Right sk ->
        SignKeyBLSMinPk (bytesToPinned "genKeyDSIGN" (BLS.secretKeyToBS sk))

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

instance ToCBOR PopDSIGN where
  toCBOR = encodeBytes . rawSerialisePopBLS
  encodedSizeExpr _ = encodedPopDSIGNSizeExpr

instance FromCBOR PopDSIGN where
  fromCBOR = do
    bs <- decodeBytes
    case rawDeserialisePopBLS bs of
      Just pop -> pure pop
      Nothing ->
        failSizeCheck
          "decodePopDSIGN"
          "proof of possession"
          bs
          (fromIntegral popByteLength)

expectSecretKey ::
  String ->
  SignKeyDSIGN BLS12381MinPkDSIGN ->
  BLS.SecretKey
expectSecretKey ctx (SignKeyBLSMinPk psb) =
  case BLS.secretKeyFromBS (psbToByteString psb) of
    Right sk -> sk
    Left err ->
      error $
        ctx <> ": invalid secret key encoding (" <> show err <> ")"

decodeVerKeyBytes ::
  VerKeyDSIGN BLS12381MinPkDSIGN ->
  Either BLS.BLSTError (BLS.PublicKey BLS.Curve1)
decodeVerKeyBytes (VerKeyBLSMinPk psb) =
  BLS.publicKeyFromCompressedBS @BLS.Curve1 (psbToByteString psb)

decodeSignatureBytes ::
  SigDSIGN BLS12381MinPkDSIGN ->
  Either BLS.BLSTError (BLS.Signature BLS.Curve1)
decodeSignatureBytes (SigBLSMinPk psb) =
  BLS.signatureFromCompressedBS @BLS.Curve1 (psbToByteString psb)

bytesToPinned ::
  forall n.
  KnownNat n =>
  String ->
  ByteString ->
  PinnedSizedBytes n
bytesToPinned ctx bs =
  fromMaybe
    (error (ctx <> ": unexpected byte length " <> show (BS.length bs)))
    (psbFromByteStringCheck bs)

derivePopDSIGN ::
  ContextDSIGN BLS12381MinPkDSIGN ->
  SignKeyDSIGN BLS12381MinPkDSIGN ->
  ByteString ->
  PopDSIGN
derivePopDSIGN (mdst, maug) sk pinBytes =
  let effDst = Just (fromMaybe defaultDst mdst)
      effAug = Just (fromMaybe pinBytes maug)
      blsSk = expectSecretKey "derivePopDSIGN" sk
      pop = BLS.blsProofOfPossessionProve @BLS.Curve1 blsSk effDst effAug
      popBytes = serializePopProof pop
   in PopDSIGN (bytesToPinned "derivePopDSIGN" popBytes)

verifyPopDSIGN ::
  ContextDSIGN BLS12381MinPkDSIGN ->
  VerKeyDSIGN BLS12381MinPkDSIGN ->
  ByteString ->
  PopDSIGN ->
  Bool
verifyPopDSIGN (mdst, maug) vkBytes pinBytes (PopDSIGN popPsb) =
  let effDst = Just (fromMaybe defaultDst mdst)
      effAug = Just (fromMaybe pinBytes maug)
   in case ( decodeVerKeyBytes vkBytes
           , validatePopBytes (psbToByteString popPsb)
           ) of
        (Right vk, Just popProof) ->
          BLS.blsProofOfPossessionVerify @BLS.Curve1 vk popProof effDst effAug
        _ -> False
