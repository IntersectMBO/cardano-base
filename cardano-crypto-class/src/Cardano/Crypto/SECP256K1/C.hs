{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Crypto.SECP256K1.C (
  SECP256k1Context,
  secpContextSignVerify,
  SECP256k1SchnorrExtraParams,
  secpContextCreate,
  secpContextDestroy,
  secpKeyPairCreate,
  secpSchnorrSigSignCustom,
  secpKeyPairXOnlyPub,
  secpSchnorrSigVerify,
  secpXOnlyPubkeySerialize,
  secpXOnlyPubkeyParse,
  ) where

import Data.Bits ((.|.))
import Foreign.Ptr (Ptr)
import Data.Word (Word8)
import Foreign.C.Types (CUChar, CSize (CSize), CInt (CInt))
import Cardano.Foreign (SizedPtr (SizedPtr))
import Cardano.Crypto.SECP256K1.Constants (
  SECP256K1_KEYPAIR_BYTES,
  SECP256K1_PRIVKEY_BYTES,
  SECP256K1_SCHNORR_SIGNATURE_BYTES,
  SECP256K1_XONLY_PUBKEY_BYTES,
  SECP256K1_PUBKEY_BYTES,
  )

data SECP256k1Context

data SECP256k1SchnorrExtraParams

foreign import capi "secp256k1.h secp256k1_context_create"
  secpContextCreate :: 
     CInt -- flags
  -> IO (Ptr SECP256k1Context)

foreign import capi "secp256k1.h secp256k1_context_destroy"
  secpContextDestroy :: 
     Ptr SECP256k1Context
  -> IO ()

foreign import capi "secp256k1.h value SECP256K1_CONTEXT_SIGN"
  secpContextSign :: CInt

foreign import capi "secp256k1.h value SECP256K1_CONTEXT_VERIFY"
  secpContextVerify :: CInt

secpContextSignVerify :: CInt
secpContextSignVerify = secpContextSign .|. secpContextVerify

foreign import capi "secp256k1_extrakeys.h secp256k1_keypair_create"
  secpKeyPairCreate :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> SizedPtr SECP256K1_KEYPAIR_BYTES -- out-param for keypair to initialize
  -> SizedPtr SECP256K1_PRIVKEY_BYTES -- secret key (32 bytes)
  -> IO CInt -- 1 on success, 0 on failure

foreign import capi "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign_custom"
  secpSchnorrSigSignCustom :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> SizedPtr SECP256K1_SCHNORR_SIGNATURE_BYTES -- out-param for signature (64 bytes)
  -> Ptr CUChar -- message to sign
  -> CSize -- message length in bytes
  -> SizedPtr SECP256K1_KEYPAIR_BYTES -- initialized keypair
  -> Ptr SECP256k1SchnorrExtraParams -- not used
  -> IO CInt -- 1 on success, 0 on failure

foreign import capi "secp256k1_extrakeys.h secp256k1_keypair_xonly_pub"
  secpKeyPairXOnlyPub :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_XONLY_PUBKEY_BYTES -- out-param for xonly pubkey
  -> Ptr CInt -- parity (not used)
  -> SizedPtr SECP256K1_KEYPAIR_BYTES -- keypair
  -> IO CInt -- 1 on success, 0 on error

foreign import capi "secp256k1_schnorrsig.h secp256k1_schnorrsig_verify"
  secpSchnorrSigVerify :: 
     Ptr SECP256k1Context -- context initialized for verifying
  -> SizedPtr SECP256K1_SCHNORR_SIGNATURE_BYTES -- signature to verify (64 bytes)
  -> Ptr CUChar -- message to verify
  -> CSize -- message length in bytes
  -> SizedPtr SECP256K1_XONLY_PUBKEY_BYTES -- pubkey to verify with
  -> CInt -- 1 on success, 0 on failure

foreign import capi "secp256k1_extrakeys.h secp256k1_xonly_pubkey_serialize"
  secpXOnlyPubkeySerialize :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_PUBKEY_BYTES -- out-param for serialized representation
  -> SizedPtr SECP256K1_XONLY_PUBKEY_BYTES -- the xonly pubkey to serialize
  -> IO CInt -- 1 on success, 0 on error

foreign import capi "secp256k1_extrakeys.h secp256k1_xonly_pubkey_parse"
  secpXOnlyPubkeyParse ::
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_XONLY_PUBKEY_BYTES -- out-param for deserialized representation
  -> Ptr Word8 -- bytes to deserialize
  -> IO CInt -- 1 if the parse succeeded, 0 if the parse failed (due to invalid representation)
