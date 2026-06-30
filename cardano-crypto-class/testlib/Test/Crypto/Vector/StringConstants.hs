{-# LANGUAGE TypeApplications #-}

module Test.Crypto.Vector.StringConstants (
  invalidEcdsaSigLengthError,
  invalidSchnorrVerKeyLengthError,
  invalidEcdsaVerKeyLengthError,
  invalidSchnorrSigLengthError,
  cannotDecodeVerificationKeyError,
  unexpectedDecodingError,
)
where

import Cardano.Crypto.SECP256K1.Constants (
  SECP256K1_ECDSA_PUBKEY_BYTES,
  SECP256K1_ECDSA_SIGNATURE_BYTES,
  SECP256K1_SCHNORR_PUBKEY_BYTES,
  SECP256K1_SCHNORR_SIGNATURE_BYTES,
 )
import Data.Data (Proxy (Proxy))
import GHC.TypeLits (natVal)

invalidEcdsaVerKeyLengthError :: Integer -> String
invalidEcdsaVerKeyLengthError =
  wrongLengthError "VerKeyDSIGN EcdsaSecp256k1DSIGN" $ natVal $ Proxy @SECP256K1_ECDSA_PUBKEY_BYTES

invalidSchnorrVerKeyLengthError :: Integer -> String
invalidSchnorrVerKeyLengthError =
  wrongLengthError "VerKeyDSIGN SchnorrSecp256k1DSIGN" $
    natVal $
      Proxy @SECP256K1_SCHNORR_PUBKEY_BYTES

invalidEcdsaSigLengthError :: Integer -> String
invalidEcdsaSigLengthError =
  wrongLengthError "SigDSIGN EcdsaSecp256k1DSIGN" $ natVal $ Proxy @SECP256K1_ECDSA_SIGNATURE_BYTES

-- | The Schnorr signature decoder validates length via the underlying
-- 'PinnedSizedBytes', so the error is tagged with that type rather than the
-- DSIGN type.
invalidSchnorrSigLengthError :: Integer -> String
invalidSchnorrSigLengthError =
  wrongLengthError ("PinnedSizedBytes " ++ show schnorrSigSize) schnorrSigSize
  where
    schnorrSigSize = natVal $ Proxy @SECP256K1_SCHNORR_SIGNATURE_BYTES

wrongLengthError :: String -> Integer -> Integer -> String
wrongLengthError typeName expectedLength actualLength =
  typeName
    ++ ": wrong length, expected "
    ++ show expectedLength
    ++ " bytes but got "
    ++ show actualLength

cannotDecodeVerificationKeyError :: String
cannotDecodeVerificationKeyError = "VerKeyDSIGN SchnorrSecp256k1DSIGN: deserialisation failed"

unexpectedDecodingError :: String
unexpectedDecodingError = "Test failed. Unexpected decoding error encountered."
