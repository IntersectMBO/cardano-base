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

-- | BLS12-381 digital signatures (minimal signature size variant).
module Cardano.Crypto.DSIGN.BLS12381MinSig (
  BLS12381MinSigDSIGN,
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
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import GHC.TypeLits (KnownNat, Nat)
import NoThunks.Class (NoThunks, OnlyCheckWhnfNamed (..))

import qualified Cardano.Crypto.EllipticCurve.BLS12_381.Internal as BLS

-- | Algorithm marker for BLS12-381 Minimal-signature-size:
-- public keys on G2 (96B), signatures on G1 (48B), secret key 32B.
data BLS12381MinSigDSIGN

defaultDst :: ByteString
defaultDst = "BLS_DST_CARDANO_BASE_V1"

type BlsSecretKeyBytes = 32 :: Nat
type BlsMinSigVerKeyBytes = 96 :: Nat
type BlsMinSigSigBytes = 48 :: Nat
type BlsMinSigPopBytes = 96 :: Nat

newtype PopDSIGN
  = PopDSIGN (PinnedSizedBytes BlsMinSigPopBytes)
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
  BLS.compressedSizePoint (Proxy @(BLS.Dual BLS.Curve2))

serializePopProof ::
  BLS.ProofOfPossession BLS.Curve2 ->
  ByteString
serializePopProof (BLS.ProofOfPossession mu1 mu2) =
  BLS.blsCompress mu1 <> BLS.blsCompress mu2

validatePopBytes ::
  ByteString ->
  Maybe (BLS.ProofOfPossession BLS.Curve2)
validatePopBytes bs
  | BS.length bs /= popByteLength = Nothing
  | otherwise = do
      let (mu1Bytes, mu2Bytes) = BS.splitAt compressedPopElementLength bs
      mu1 <- decodeMu1 mu1Bytes
      mu2 <- decodeMu2 mu2Bytes
      pure (BLS.ProofOfPossession mu1 mu2)
  where
    decodeMu1 bytes =
      case BLS.blsUncompress @(BLS.Dual BLS.Curve2) bytes of
        Right point
          | BLS.blsIsInf point -> Nothing
          | otherwise -> Just point
        Left _ -> Nothing
    decodeMu2 bytes =
      case BLS.blsUncompress @(BLS.Dual BLS.Curve2) bytes of
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

instance DSIGNAlgorithm BLS12381MinSigDSIGN where
  type SeedSizeDSIGN BLS12381MinSigDSIGN = 32
  type SizeVerKeyDSIGN BLS12381MinSigDSIGN = 96 -- G2 compressed
  type SizeSignKeyDSIGN BLS12381MinSigDSIGN = 32 -- scalar
  type SizeSigDSIGN BLS12381MinSigDSIGN = 48 -- G1 compressed

  type Signable BLS12381MinSigDSIGN = SignableRepresentation
  type ContextDSIGN BLS12381MinSigDSIGN = (Maybe ByteString, Maybe ByteString)

  newtype VerKeyDSIGN BLS12381MinSigDSIGN
    = VerKeyBLSMinSig (PinnedSizedBytes BlsMinSigVerKeyBytes)
    deriving stock (Generic)
    deriving newtype (Eq, Show)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "VerKeyDSIGN BLS12381MinSigDSIGN"
            (VerKeyDSIGN BLS12381MinSigDSIGN)
  newtype SignKeyDSIGN BLS12381MinSigDSIGN
    = SignKeyBLSMinSig (PinnedSizedBytes BlsSecretKeyBytes)
    deriving stock (Generic)
    deriving newtype (Eq, Show)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SignKeyDSIGN BLS12381MinSigDSIGN"
            (SignKeyDSIGN BLS12381MinSigDSIGN)
  newtype SigDSIGN BLS12381MinSigDSIGN
    = SigBLSMinSig (PinnedSizedBytes BlsMinSigSigBytes)
    deriving stock (Generic)
    deriving newtype (Eq, Show)
    deriving
      (NoThunks)
      via OnlyCheckWhnfNamed
            "SigDSIGN BLS12381MinSigDSIGN"
            (SigDSIGN BLS12381MinSigDSIGN)

  algorithmNameDSIGN _ = "bls12-381-minsig"

  rawSerialiseVerKeyDSIGN (VerKeyBLSMinSig vk) = psbToByteString vk
  rawSerialiseSignKeyDSIGN (SignKeyBLSMinSig sk) = psbToByteString sk
  rawSerialiseSigDSIGN (SigBLSMinSig sig) = psbToByteString sig

  rawDeserialiseVerKeyDSIGN bs =
    case BLS.publicKeyFromCompressedBS @BLS.Curve2 bs of
      Left _ -> Nothing
      Right _ -> VerKeyBLSMinSig <$> psbFromByteStringCheck bs

  rawDeserialiseSignKeyDSIGN bs =
    SignKeyBLSMinSig <$> psbFromByteStringCheck bs

  rawDeserialiseSigDSIGN bs =
    case BLS.signatureFromCompressedBS @BLS.Curve2 bs of
      Left _ -> Nothing
      Right _ -> SigBLSMinSig <$> psbFromByteStringCheck bs

  deriveVerKeyDSIGN sk =
    let blsSk = expectSecretKey "deriveVerKeyDSIGN" sk
        vk = BLS.blsSkToPk @BLS.Curve2 blsSk
     in VerKeyBLSMinSig (bytesToPinned "deriveVerKeyDSIGN" (BLS.publicKeyToCompressedBS vk))

  signDSIGN (mdst, maug) a skBytes =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
        blsSk = expectSecretKey "signDSIGN" skBytes
        sig = BLS.blsSign @BLS.Curve2 Proxy blsSk msg effDst effAug
     in SigBLSMinSig (bytesToPinned "signDSIGN" (BLS.signatureToCompressedBS @BLS.Curve2 sig))

  verifyDSIGN (mdst, maug) vkBytes a sigBytes =
    let msg = getSignableRepresentation a
        effDst = Just (fromMaybe defaultDst mdst)
        effAug = Just (fromMaybe mempty maug)
     in case ( decodeVerKeyBytes vkBytes
             , decodeSignatureBytes sigBytes
             ) of
          (Right vk, Right sig) ->
            if BLS.blsSignatureVerify @BLS.Curve2 vk msg sig effDst effAug
              then Right ()
              else Left "verifyDSIGN (BLS minsig): verification failed"
          (Left _, _) -> Left "verifyDSIGN (BLS minsig): invalid verification key"
          (_, Left _) -> Left "verifyDSIGN (BLS minsig): invalid signature"

  genKeyDSIGN seed =
    case BLS.blsKeyGen (getSeedBytes seed) Nothing of
      Left _ -> error "genKeyDSIGN (BLS minsig): invalid seed (needs >=32 bytes)"
      Right sk ->
        SignKeyBLSMinSig (bytesToPinned "genKeyDSIGN" (BLS.secretKeyToBS sk))

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
  SignKeyDSIGN BLS12381MinSigDSIGN ->
  BLS.SecretKey
expectSecretKey ctx (SignKeyBLSMinSig psb) =
  case BLS.secretKeyFromBS (psbToByteString psb) of
    Right sk -> sk
    Left err ->
      error $
        ctx <> ": invalid secret key encoding (" <> show err <> ")"

decodeVerKeyBytes ::
  VerKeyDSIGN BLS12381MinSigDSIGN ->
  Either BLS.BLSTError (BLS.PublicKey BLS.Curve2)
decodeVerKeyBytes (VerKeyBLSMinSig psb) =
  BLS.publicKeyFromCompressedBS @BLS.Curve2 (psbToByteString psb)

decodeSignatureBytes ::
  SigDSIGN BLS12381MinSigDSIGN ->
  Either BLS.BLSTError (BLS.Signature BLS.Curve2)
decodeSignatureBytes (SigBLSMinSig psb) =
  BLS.signatureFromCompressedBS @BLS.Curve2 (psbToByteString psb)

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
  ContextDSIGN BLS12381MinSigDSIGN ->
  SignKeyDSIGN BLS12381MinSigDSIGN ->
  ByteString ->
  PopDSIGN
derivePopDSIGN (mdst, maug) sk pinBytes =
  let effDst = Just (fromMaybe defaultDst mdst)
      effAug = Just (fromMaybe pinBytes maug)
      blsSk = expectSecretKey "derivePopDSIGN" sk
      pop = BLS.blsProofOfPossessionProve @BLS.Curve2 blsSk effDst effAug
      popBytes = serializePopProof pop
   in PopDSIGN (bytesToPinned "derivePopDSIGN" popBytes)

verifyPopDSIGN ::
  ContextDSIGN BLS12381MinSigDSIGN ->
  VerKeyDSIGN BLS12381MinSigDSIGN ->
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
          BLS.blsProofOfPossessionVerify @BLS.Curve2 vk popProof effDst effAug
        _ -> False

-- Eq/Show/NoThunks derive via the pinned byte representation.
