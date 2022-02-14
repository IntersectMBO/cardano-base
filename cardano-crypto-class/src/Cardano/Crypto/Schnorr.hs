{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Cardano.Crypto.Schnorr (
  schnorrNonceFunction,
  SECP256k1Context,
  secpContextNoPrecomp,
  secpContextCreate,
  secpContextDestroy,
  SECP256k1KeyPair,
  secpKeyPairCreate,
  secpSchnorrSigSign,
  SECP256k1XOnlyPubKey,
  secpSchnorrSigVerify,
  ) where

import Data.Primitive.Ptr (copyPtr)
import Data.Word (Word8)
import Data.Primitive.ByteArray (
  ByteArray, 
  newAlignedPinnedByteArray,
  byteArrayContents,
  mutableByteArrayContents,
  unsafeFreezeByteArray,
  )
import Foreign.Storable (Storable (sizeOf, alignment, peek, poke))
import Foreign.Ptr (Ptr, castPtr)
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

foreign import capi "secp256k1.h value secp256k1_context_no_precomp"
  secpContextNoPrecomp :: Ptr SECP256k1Context

foreign import capi "secp256k1.h secp256k1_context_create"
  secpContextCreate :: 
     CInt -- flags
  -> IO (Ptr SECP256k1Context)

foreign import capi "secp256k1.h secp256k1_context_destroy"
  secpContextDestroy :: 
     Ptr SECP256k1Context
  -> IO ()

newtype SECP256k1KeyPair = SECP256k1KeyPair ByteArray
  deriving (Eq, Ord) via ByteArray
  deriving stock (Show)

instance Storable SECP256k1KeyPair where
  {-# INLINEABLE sizeOf #-}
  sizeOf _ = 96
  {-# INLINEABLE alignment #-}
  alignment _ = 96
  {-# INLINEABLE peek #-}
  peek p = do
    let pBytes :: Ptr Word8 = castPtr p
    mba <- newAlignedPinnedByteArray 96 96
    let mbaPtr = mutableByteArrayContents mba
    copyPtr mbaPtr pBytes 96
    SECP256k1KeyPair <$> unsafeFreezeByteArray mba
  {-# INLINEABLE poke #-}
  poke p (SECP256k1KeyPair ba) = do
    let pBytes :: Ptr Word8 = castPtr p
    let baPtr = byteArrayContents ba
    copyPtr pBytes baPtr 96

foreign import capi "secp256k1_extrakeys.h secp256k1_keypair_create"
  secpKeyPairCreate :: 
     Ptr SECP256k1Context -- context initialized for signing
  -> Ptr SECP256k1KeyPair -- out-param for keypair to initialize
  -> Ptr CUChar -- secret key (32 bytes)
  -> Ptr CInt -- 1 on success, 0 on failure

foreign import capi "secp256k1_schnorrsig.h secp256k1_schnorrsig_sign"
  secpSchnorrSigSign ::
     Ptr SECP256k1Context -- context initialized for signing
  -> Ptr CUChar -- out-param for signature (64 bytes)
  -> Ptr CUChar -- message hash to sign (32 bytes)
  -> Ptr SECP256k1KeyPair -- initialized keypair
  -> Ptr CUChar -- fresh randomness (32 bytes)
  -> IO CInt -- 1 on success, 0 on failure

newtype SECP256k1XOnlyPubKey = SECP256k1XOnlyPubKey ByteArray
  deriving (Eq, Ord) via ByteArray
  deriving stock (Show)

instance Storable SECP256k1XOnlyPubKey where
  {-# INLINEABLE sizeOf #-}
  sizeOf _ = 64
  {-# INLINEABLE alignment #-}
  alignment _ = 64
  {-# INLINEABLE peek #-}
  peek p = do
    let pBytes :: Ptr Word8 = castPtr p
    mba <- newAlignedPinnedByteArray 64 64
    let mbaPtr = mutableByteArrayContents mba
    copyPtr mbaPtr pBytes 64
    SECP256k1XOnlyPubKey <$> unsafeFreezeByteArray mba
  {-# INLINEABLE poke #-}
  poke p (SECP256k1XOnlyPubKey ba) = do
    let pBytes :: Ptr Word8 = castPtr p
    let baPtr = byteArrayContents ba
    copyPtr pBytes baPtr 64

foreign import capi "secp256k1_schnorrsig.h secp256k1_schnorrsig_verify"
  secpSchnorrSigVerify :: 
     Ptr SECP256k1Context -- context initialized for verifying
  -> Ptr CUChar -- signature to verify (64 bytes)
  -> Ptr CUChar -- message to verify
  -> CSize -- message length in bytes
  -> Ptr SECP256k1XOnlyPubKey -- pubkey to verify with
  -> CInt -- 1 on success, 0 on failure
