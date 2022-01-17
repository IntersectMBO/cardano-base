{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-orphans #-} -- need NoThunks for secp256k1-haskell types

module Cardano.Crypto.DSIGN.SECP256k1 where

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (toCBOR, encodedSizeExpr))
import Data.ByteString (ByteString)
import Crypto.Random (getRandomBytes)
import Cardano.Crypto.Seed (runMonadRandomWithSeed)
import Data.Serialize (Serialize (get, put), runPut, runGet)
import Data.Kind (Type)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import qualified Crypto.Secp256k1 as SECP
import NoThunks.Class (NoThunks)
import Cardano.Crypto.DSIGN.Class (
  DSIGNAlgorithm (VerKeyDSIGN, 
                  SignKeyDSIGN, 
                  SigDSIGN,
                  SeedSizeDSIGN, 
                  SizeSigDSIGN, 
                  SizeSignKeyDSIGN, 
                  SizeVerKeyDSIGN, 
                  algorithmNameDSIGN,
                  deriveVerKeyDSIGN, 
                  signDSIGN, 
                  verifyDSIGN, 
                  genKeyDSIGN, 
                  rawSerialiseSigDSIGN,
                  Signable, 
                  rawSerialiseVerKeyDSIGN, 
                  rawSerialiseSignKeyDSIGN, 
                  rawDeserialiseVerKeyDSIGN,
                  rawDeserialiseSignKeyDSIGN, 
                  rawDeserialiseSigDSIGN), 
  encodeVerKeyDSIGN, 
  encodedVerKeyDSIGNSizeExpr, 
  decodeVerKeyDSIGN, 
  encodeSignKeyDSIGN, 
  encodedSignKeyDESIGNSizeExpr, 
  decodeSignKeyDSIGN, 
  encodeSigDSIGN, 
  encodedSigDSIGNSizeExpr, 
  decodeSigDSIGN
  )

data SECP256k1DSIGN

instance NoThunks (VerKeyDSIGN SECP256k1DSIGN)

instance NoThunks (SignKeyDSIGN SECP256k1DSIGN)

instance NoThunks (SigDSIGN SECP256k1DSIGN)

instance DSIGNAlgorithm SECP256k1DSIGN where
  type SeedSizeDSIGN SECP256k1DSIGN = 32
  type SizeSigDSIGN SECP256k1DSIGN = 72
  type SizeSignKeyDSIGN SECP256k1DSIGN = 32
  type SizeVerKeyDSIGN SECP256k1DSIGN = 33 -- approximate, as it's 257 bits
  type Signable SECP256k1DSIGN = ((~) SECP.Msg)
  newtype VerKeyDSIGN SECP256k1DSIGN = VerKeySECP256k1 SECP.PubKey
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  newtype SignKeyDSIGN SECP256k1DSIGN = SignKeySECP256k1 SECP.SecKey
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  newtype SigDSIGN SECP256k1DSIGN = SigSECP256k1 SECP.Sig
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
  algorithmNameDSIGN _ = "secp256k1"
  deriveVerKeyDSIGN (SignKeySECP256k1 sk) = VerKeySECP256k1 . SECP.derivePubKey $ sk
  signDSIGN () msg (SignKeySECP256k1 k) = SigSECP256k1 . SECP.signMsg k $ msg
  verifyDSIGN () (VerKeySECP256k1 pk) msg (SigSECP256k1 sig) = 
    if SECP.verifySig pk sig msg
    then pure ()
    else Left "SECP256k1 signature not verified"
  genKeyDSIGN seed = runMonadRandomWithSeed seed $ do
    bs <- getRandomBytes 32
    case SECP.secKey bs of 
      Nothing -> error "Failed to construct a SECP256k1 secret key unexpectedly"
      Just sk -> pure . SignKeySECP256k1 $ sk
  rawSerialiseSigDSIGN (SigSECP256k1 sig) = putting sig
  rawSerialiseVerKeyDSIGN (VerKeySECP256k1 pk) = putting pk
  rawSerialiseSignKeyDSIGN (SignKeySECP256k1 sk) = putting sk
  rawDeserialiseVerKeyDSIGN bs = VerKeySECP256k1 <$> (eitherToMaybe . getting $ bs)
  rawDeserialiseSignKeyDSIGN bs = SignKeySECP256k1 <$> (eitherToMaybe . getting $ bs)
  rawDeserialiseSigDSIGN bs = SigSECP256k1 <$> (eitherToMaybe . getting $ bs)

instance ToCBOR (VerKeyDSIGN SECP256k1DSIGN) where
  toCBOR = encodeVerKeyDSIGN
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN SECP256k1DSIGN) where
  fromCBOR = decodeVerKeyDSIGN

instance ToCBOR (SignKeyDSIGN SECP256k1DSIGN) where
  toCBOR = encodeSignKeyDSIGN
  encodedSizeExpr _ = encodedSignKeyDESIGNSizeExpr

instance FromCBOR (SignKeyDSIGN SECP256k1DSIGN) where
  fromCBOR = decodeSignKeyDSIGN

instance ToCBOR (SigDSIGN SECP256k1DSIGN) where
  toCBOR = encodeSigDSIGN
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN SECP256k1DSIGN) where
  fromCBOR = decodeSigDSIGN

-- Required orphans

instance NoThunks SECP.PubKey

instance NoThunks SECP.SecKey

instance NoThunks SECP.Sig

-- Helpers

eitherToMaybe :: forall (a :: Type) (b :: Type) . 
  Either b a -> Maybe a
eitherToMaybe = either (const Nothing) pure

putting :: forall (a :: Type) . (Serialize a) => a -> ByteString
putting = runPut . put

getting :: forall (a :: Type) . (Serialize a) => ByteString -> Either String a
getting = runGet get
