{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Crypto.Schnorr (
  schnorrNonceFunction,
  SECP256k1Context,
  secpContextSignVerify,
  SECP256k1SchnorrExtraParams,
  SECP256k1SecKey,
  SECP256k1SchnorrSig,
  secpContextCreate,
  secpContextDestroy,
  SECP256k1KeyPair,
  secpKeyPairCreate,
  secpSchnorrSigSign,
  secpSchnorrSigSignCustom,
  SECP256k1XOnlyPubKey,
  secpKeyPairXOnlyPub,
  secpSchnorrSigVerify,
  ) where

import Data.Bits ((.|.))
import Foreign.Ptr (Ptr)
import Foreign.C.Types (CUChar, CSize (CSize), CInt (CInt))

foreign import capi "secp256k1_schnorrsig.h secp256k1_nonce_function_bip340" 
  schnorrNonceFunction :: 
     Ptr CUChar -- out-param for nonce (32 bytes)
  -> Ptr CUChar -- message being verified, only NULL when message length is 0
  -> CSize -- message length
  -> Ptr CUChar -- secret key (not NULL, 32 bytes)
  -> Ptr CUChar -- serialized xonly pubkey corresponding to secret key (not NULL, 32 bytes)
  -> Ptr CUChar -- description of algorithm (not NULL)
  -> CSize -- length of algorithm description
  -> Ptr CUChar -- arbitrary passthrough data
  -> IO CInt -- 1 on success, 0 on error

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

foreign import capi "secp256k1.h SECP256k1_CONTEXT_SIGN"
  secpContextSign :: CInt

foreign import capi "secp256k1.h SECP256k1_CONTEXT_VERIFY"
  secpContextVerify :: CInt

secpContextSignVerify :: CInt
secpContextSignVerify = secpContextSign .|. secpContextVerify

data SECP256k1SecKey

data SECP256k1SchnorrSig

data SECP256k1KeyPair

foreign import capi "secp256k1_extrakeys.h secp256k1_keypair_create"
  secpKeyPairCreate :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> Ptr SECP256k1KeyPair -- out-param for keypair to initialize
  -> Ptr CUChar -- secret key (32 bytes)
  -> IO CInt -- 1 on success, 0 on failure

foreign import capi "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign"
  secpSchnorrSigSign ::
     Ptr SECP256k1Context -- context initialized for signing
  -> Ptr SECP256k1SchnorrSig -- out-param for signature (64 bytes)
  -> Ptr CUChar -- message hash to sign (32 bytes)
  -> Ptr SECP256k1KeyPair -- initialized keypair
  -> Ptr CUChar -- fresh randomness (32 bytes)
  -> IO CInt -- 1 on success, 0 on failure

foreign import capi "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign_custom"
  secpSchnorrSigSignCustom :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> Ptr SECP256k1SchnorrSig -- out-param for signature (64 bytes)
  -> Ptr CUChar -- message to sign
  -> CSize -- message length in bytes
  -> Ptr SECP256k1KeyPair -- initialized keypair
  -> Ptr SECP256k1SchnorrExtraParams -- not used
  -> IO CInt -- 1 on success, 0 on failure

data SECP256k1XOnlyPubKey

foreign import capi "secp256k1_extrakeys.h secp256k1_keypair_xonly_pub"
  secpKeyPairXOnlyPub :: 
     Ptr SECP256k1Context -- an initialized context
  -> Ptr SECP256k1XOnlyPubKey -- out-param for xonly pubkey
  -> Ptr CInt -- parity (not used)
  -> Ptr SECP256k1KeyPair -- keypair
  -> IO CInt -- 1 on success, 0 on error

foreign import capi "secp256k1_schnorrsig.h secp256k1_schnorrsig_verify"
  secpSchnorrSigVerify :: 
     Ptr SECP256k1Context -- context initialized for verifying
  -> Ptr CUChar -- signature to verify (64 bytes)
  -> Ptr CUChar -- message to verify
  -> CSize -- message length in bytes
  -> Ptr SECP256k1XOnlyPubKey -- pubkey to verify with
  -> CInt -- 1 on success, 0 on failure
