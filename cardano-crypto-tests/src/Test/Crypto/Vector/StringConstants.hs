
{-# LANGUAGE TypeApplications #-}

module Test.Crypto.Vector.StringConstants
  ( invalidEcdsaSigLengthError,
    invalidSchnorrVerKeyLengthError,
    invalidEcdsaVerKeyLengthError,
    invalidSchnorrSigLengthError,
    cannotDecodeVerificationKeyError,
    unexpectedDecodingError,
  )
where

import Data.Data (Proxy (Proxy))
import GHC.TypeLits (natVal)
import Cardano.Crypto.SECP256K1.Constants (SECP256K1_ECDSA_PUBKEY_BYTES, SECP256K1_SCHNORR_PUBKEY_BYTES, SECP256K1_ECDSA_SIGNATURE_BYTES, SECP256K1_SCHNORR_SIGNATURE_BYTES)

invalidEcdsaVerKeyLengthError :: Integer -> String
invalidEcdsaVerKeyLengthError = invalidVerKeyLengthError $ natVal $ Proxy @SECP256K1_ECDSA_PUBKEY_BYTES

invalidSchnorrVerKeyLengthError :: Integer -> String
invalidSchnorrVerKeyLengthError = invalidVerKeyLengthError $ natVal $ Proxy @SECP256K1_SCHNORR_PUBKEY_BYTES

invalidVerKeyLengthError :: Integer -> Integer -> String
invalidVerKeyLengthError expectedLength actualLength =
  "decodeVerKeyDSIGN: wrong length, expected " ++ show expectedLength ++ " bytes but got " ++ show actualLength

invalidEcdsaSigLengthError :: Integer -> String
invalidEcdsaSigLengthError = invalidSigLengthError $ natVal $ Proxy @SECP256K1_ECDSA_SIGNATURE_BYTES

invalidSchnorrSigLengthError :: Integer -> String
invalidSchnorrSigLengthError = invalidSigLengthError $ natVal $ Proxy @SECP256K1_SCHNORR_SIGNATURE_BYTES

invalidSigLengthError :: Integer -> Integer -> String
invalidSigLengthError expectedLength actualLength =
  "decodeSigDSIGN: wrong length, expected " ++ show expectedLength ++ " bytes but got " ++ show actualLength

cannotDecodeVerificationKeyError :: String
cannotDecodeVerificationKeyError = "decodeVerKeyDSIGN: cannot decode"

unexpectedDecodingError :: String
unexpectedDecodingError = "Test failed. Unexpected decoding error encountered."
