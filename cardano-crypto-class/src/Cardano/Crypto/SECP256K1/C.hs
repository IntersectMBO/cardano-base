{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}

module Cardano.Crypto.SECP256K1.C (
  SECP256k1Context,
  secpContextSignVerify,
  SECP256k1SchnorrExtraParams,
  secpContextCreate,
--  secpContextDestroy,
  secpKeyPairCreate,
  secpSchnorrSigSignCustom,
  secpKeyPairXOnlyPub,
  secpSchnorrSigVerify,
  secpXOnlyPubkeySerialize,
  secpXOnlyPubkeyParse,
  secpCtxPtr,
  secpEcPubkeyCreate,
  secpEcdsaSign,
  secpEcdsaVerify,
  secpEcCompressed,
  secpEcPubkeySerialize,
  secpEcdsaSignatureSerializeCompact,
  secpEcdsaSignatureParseCompact,
  secpEcPubkeyParse,
  ) where

import Control.Exception (mask_)
import Data.Bits ((.|.))
import Foreign.ForeignPtr (ForeignPtr, FinalizerPtr, newForeignPtr)
import Foreign.Ptr (Ptr)
import System.IO.Unsafe (unsafePerformIO)
import Foreign.C.Types (CUChar, CSize (CSize), CInt (CInt), CUInt (CUInt))
import Cardano.Foreign (SizedPtr (SizedPtr))
import Cardano.Crypto.SECP256K1.Constants (
  SECP256K1_SCHNORR_KEYPAIR_BYTES,
  SECP256K1_SCHNORR_PRIVKEY_BYTES,
  SECP256K1_SCHNORR_SIGNATURE_BYTES,
  SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL,
  SECP256K1_SCHNORR_PUBKEY_BYTES,
  SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL,
  SECP256K1_ECDSA_PRIVKEY_BYTES,
  SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL,
  SECP256K1_ECDSA_SIGNATURE_BYTES,
  SECP256K1_ECDSA_MESSAGE_BYTES,
  )

data SECP256k1Context

data SECP256k1SchnorrExtraParams

-- We create a single context for both signing and verifying, which we use
-- everywhere. This saves considerable time, and is safe, provided nobody
-- outside cardano-base gets to touch it.
--
-- We do _not_ make this dupable, as the whole point is _not_ to compute it more
-- than once!
{-# NOINLINE secpCtxPtr #-}
secpCtxPtr :: ForeignPtr SECP256k1Context
secpCtxPtr = unsafePerformIO . mask_ $ do
  ctx <- secpContextCreate secpContextSignVerify
  newForeignPtr secpContextDestroy ctx

foreign import ccall unsafe "secp256k1.h &secp256k1_context_destroy"
  secpContextDestroy :: FinalizerPtr SECP256k1Context

foreign import ccall unsafe "secp256k1.h secp256k1_context_create"
  secpContextCreate :: 
     CUInt -- flags
  -> IO (Ptr SECP256k1Context)

foreign import capi "secp256k1.h value SECP256K1_CONTEXT_SIGN"
  secpContextSign :: CUInt

foreign import capi "secp256k1.h value SECP256K1_CONTEXT_VERIFY"
  secpContextVerify :: CUInt

secpContextSignVerify :: CUInt
secpContextSignVerify = secpContextSign .|. secpContextVerify

foreign import capi "secp256k1.h value SECP256K1_EC_COMPRESSED"
  secpEcCompressed :: CUInt

foreign import ccall unsafe "secp256k1_extrakeys.h secp256k1_keypair_create"
  secpKeyPairCreate :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> SizedPtr SECP256K1_SCHNORR_KEYPAIR_BYTES -- out-param for keypair to initialize
  -> SizedPtr SECP256K1_SCHNORR_PRIVKEY_BYTES -- secret key (32 bytes)
  -> IO CInt -- 1 on success, 0 on failure

foreign import ccall unsafe "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign_custom"
  secpSchnorrSigSignCustom :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> SizedPtr SECP256K1_SCHNORR_SIGNATURE_BYTES -- out-param for signature (64 bytes)
  -> Ptr CUChar -- message to sign
  -> CSize -- message length in bytes
  -> SizedPtr SECP256K1_SCHNORR_KEYPAIR_BYTES -- initialized keypair
  -> Ptr SECP256k1SchnorrExtraParams -- not used
  -> IO CInt -- 1 on success, 0 on failure

foreign import ccall unsafe "secp256k1_extrakeys.h secp256k1_keypair_xonly_pub"
  secpKeyPairXOnlyPub :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL -- out-param for xonly pubkey
  -> Ptr CInt -- parity (not used)
  -> SizedPtr SECP256K1_SCHNORR_KEYPAIR_BYTES -- keypair
  -> IO CInt -- 1 on success, 0 on error

foreign import ccall unsafe "secp256k1_schnorrsig.h secp256k1_schnorrsig_verify"
  secpSchnorrSigVerify :: 
     Ptr SECP256k1Context -- context initialized for verifying
  -> SizedPtr SECP256K1_SCHNORR_SIGNATURE_BYTES -- signature to verify (64 bytes)
  -> Ptr CUChar -- message to verify
  -> CSize -- message length in bytes
  -> SizedPtr SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL -- pubkey to verify with
  -> CInt -- 1 on success, 0 on failure

foreign import ccall unsafe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_serialize"
  secpXOnlyPubkeySerialize :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_SCHNORR_PUBKEY_BYTES -- out-param for serialized representation
  -> SizedPtr SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL -- the xonly pubkey to serialize
  -> IO CInt -- 1 on success, 0 on error

foreign import ccall unsafe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_parse"
  secpXOnlyPubkeyParse ::
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL -- out-param for deserialized representation
  -> Ptr CUChar -- bytes to deserialize
  -> IO CInt -- 1 if the parse succeeded, 0 if the parse failed (due to invalid representation)

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_create" 
  secpEcPubkeyCreate :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL -- out-param for generated key
  -> SizedPtr SECP256K1_ECDSA_PRIVKEY_BYTES -- seed private key
  -> IO CInt -- 1 on success, 0 on error

foreign import ccall unsafe "secp256k1.h secp256k1_ecdsa_sign"
  secpEcdsaSign :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> SizedPtr SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL -- out-param for signature
  -> SizedPtr SECP256K1_ECDSA_MESSAGE_BYTES -- pointer to hashed message data
  -> SizedPtr SECP256K1_ECDSA_PRIVKEY_BYTES -- private key to sign with
  -> Ptr CUChar -- pointer to a nonce (not used)
  -> Ptr CUChar -- pointer to arbitrary data for nonce generation (not used)
  -> IO CInt -- 1 on success, 0 on error

foreign import ccall unsafe "secp256k1.h secp256k1_ecdsa_verify"
  secpEcdsaVerify :: 
     Ptr SECP256k1Context -- context initialized for verification
  -> SizedPtr SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL -- signature to verify
  -> SizedPtr SECP256K1_ECDSA_MESSAGE_BYTES -- pointer to hashed message data
  -> SizedPtr SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL -- public key to verify with
  -> CInt -- 1 if valid, 0 if invalid or malformed signature

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_serialize"
  secpEcPubkeySerialize :: 
     Ptr SECP256k1Context -- an initialized context
  -> Ptr CUChar -- allocated buffer to write to
  -> Ptr CSize -- pointer to number of bytes to write, will be overwritten with how much we actually wrote
  -> SizedPtr SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL -- public key to serialize
  -> CUInt -- flags (only secpEcCompressed available)
  -> IO CInt -- always 1

foreign import ccall unsafe "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
  secpEcdsaSignatureSerializeCompact :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_ECDSA_SIGNATURE_BYTES -- allocated buffer to write to
  -> SizedPtr SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL -- signature to serialize
  -> IO CInt -- always 1

foreign import ccall unsafe "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
  secpEcdsaSignatureParseCompact :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL -- allocated buffer to write to
  -> SizedPtr SECP256K1_ECDSA_SIGNATURE_BYTES -- signature to deserialize
  -> IO CInt -- 1 if parsed successfully, 0 if parse failed

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_parse"
  secpEcPubkeyParse :: 
     Ptr SECP256k1Context -- an initialized context
  -> SizedPtr SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL -- allocated buffer to write to
  -> Ptr CUChar -- input data (must be 33 bytes long)
  -> CSize -- number of bytes to read (must be 33)
  -> IO CInt -- 1 if parsed successfully, 0 if parse failed
