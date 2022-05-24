{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
-- need NoThunks for secp256k1-haskell types
{-# OPTIONS_GHC -Wno-orphans #-}

module Cardano.Crypto.DSIGN.EcdsaSecp256k1
  ( EcdsaSecp256k1DSIGN,
    VerKeyDSIGN (..),
    SignKeyDSIGN (..),
    SigDSIGN (..),
  )
where

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (encodedSizeExpr, toCBOR))
import Cardano.Crypto.DSIGN.Class
  ( DSIGNAlgorithm
      ( SeedSizeDSIGN,
        SigDSIGN,
        SignKeyDSIGN,
        Signable,
        SizeSigDSIGN,
        SizeSignKeyDSIGN,
        SizeVerKeyDSIGN,
        VerKeyDSIGN,
        algorithmNameDSIGN,
        deriveVerKeyDSIGN,
        genKeyDSIGN,
        rawDeserialiseSigDSIGN,
        rawDeserialiseSignKeyDSIGN,
        rawDeserialiseVerKeyDSIGN,
        rawSerialiseSigDSIGN,
        rawSerialiseSignKeyDSIGN,
        rawSerialiseVerKeyDSIGN,
        signDSIGN,
        verifyDSIGN
      ),
    decodeSigDSIGN,
    decodeSignKeyDSIGN,
    decodeVerKeyDSIGN,
    encodeSigDSIGN,
    encodeSignKeyDSIGN,
    encodeVerKeyDSIGN,
    encodedSigDSIGNSizeExpr,
    encodedSignKeyDESIGNSizeExpr,
    encodedVerKeyDSIGNSizeExpr,
  )
import Cardano.Crypto.Seed (runMonadRandomWithSeed)
import Control.DeepSeq (NFData)
import Crypto.Random (getRandomBytes)
import qualified Crypto.Secp256k1 as ECDSA
import Data.ByteString (ByteString)
import Data.Kind (Type)
import Data.Serialize (Serialize (get, put), runGet, runPut)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

data EcdsaSecp256k1DSIGN

instance NoThunks (VerKeyDSIGN EcdsaSecp256k1DSIGN)

instance NoThunks (SignKeyDSIGN EcdsaSecp256k1DSIGN)

instance NoThunks (SigDSIGN EcdsaSecp256k1DSIGN)

instance DSIGNAlgorithm EcdsaSecp256k1DSIGN where
  type SeedSizeDSIGN EcdsaSecp256k1DSIGN = 32
  type SizeSigDSIGN EcdsaSecp256k1DSIGN = 64
  type SizeSignKeyDSIGN EcdsaSecp256k1DSIGN = 32
  type SizeVerKeyDSIGN EcdsaSecp256k1DSIGN = 64
  type Signable EcdsaSecp256k1DSIGN = ((~) ECDSA.Msg)
  newtype VerKeyDSIGN EcdsaSecp256k1DSIGN
    = VerKeyEcdsaSecp256k1 ECDSA.PubKey
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  newtype SignKeyDSIGN EcdsaSecp256k1DSIGN
    = SignKeyEcdsaSecp256k1 ECDSA.SecKey
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  newtype SigDSIGN EcdsaSecp256k1DSIGN
    = SigEcdsaSecp256k1 ECDSA.Sig
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  algorithmNameDSIGN _ = "ecdsa-secp256k1"
  deriveVerKeyDSIGN (SignKeyEcdsaSecp256k1 sk) =
    VerKeyEcdsaSecp256k1 . ECDSA.derivePubKey $ sk
  signDSIGN () msg (SignKeyEcdsaSecp256k1 k) =
    SigEcdsaSecp256k1 . ECDSA.signMsg k $ msg
  verifyDSIGN () (VerKeyEcdsaSecp256k1 pk) msg (SigEcdsaSecp256k1 sig) =
    if ECDSA.verifySig pk sig msg
      then pure ()
      else Left "ECDSA-SECP256k1 signature not verified"
  genKeyDSIGN seed = runMonadRandomWithSeed seed $ do
    bs <- getRandomBytes 32
    case ECDSA.secKey bs of
      Nothing -> error "Failed to construct a ECDSA-SECP256k1 secret key unexpectedly"
      Just sk -> pure . SignKeyEcdsaSecp256k1 $ sk
  rawSerialiseSigDSIGN (SigEcdsaSecp256k1 sig) = putting sig
  rawSerialiseVerKeyDSIGN (VerKeyEcdsaSecp256k1 pk) = putting pk
  rawSerialiseSignKeyDSIGN (SignKeyEcdsaSecp256k1 sk) = putting sk
  rawDeserialiseVerKeyDSIGN bs =
    VerKeyEcdsaSecp256k1 <$> (eitherToMaybe . getting $ bs)
  rawDeserialiseSignKeyDSIGN bs =
    SignKeyEcdsaSecp256k1 <$> (eitherToMaybe . getting $ bs)
  rawDeserialiseSigDSIGN bs =
    SigEcdsaSecp256k1 <$> (eitherToMaybe . getting $ bs)

instance ToCBOR (VerKeyDSIGN EcdsaSecp256k1DSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN EcdsaSecp256k1DSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN EcdsaSecp256k1DSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDESIGNSizeExpr

instance FromCBOR (SignKeyDSIGN EcdsaSecp256k1DSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN EcdsaSecp256k1DSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN EcdsaSecp256k1DSIGN) where
  fromCBOR = decodeSigDSIGN

-- Required orphans

instance NoThunks ECDSA.PubKey

instance NoThunks ECDSA.SecKey

instance NoThunks ECDSA.Sig

-- Helpers

eitherToMaybe ::
  forall (a :: Type) (b :: Type).
  Either b a ->
  Maybe a
eitherToMaybe = either (const Nothing) pure

putting :: forall (a :: Type). (Serialize a) => a -> ByteString
putting = runPut . put

getting :: forall (a :: Type). (Serialize a) => ByteString -> Either String a
getting = runGet get
