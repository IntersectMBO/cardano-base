{-# LANGUAGE CApiFFI             #-}
{-# LANGUAGE DerivingStrategies  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Cardano.Crypto.Libsodium.C (
    -- * Initialization
    c_sodium_init,
    -- * Memory management
    c_sodium_memzero,
    c_sodium_malloc,
    c_sodium_free,
    c_sodium_free_funptr,
    -- * Hashing
    -- ** SHA256
    c_crypto_hash_sha256,
    CryptoSha256State,
    c_crypto_hash_sha256_final,
    c_crypto_hash_sha256_init,
    c_crypto_hash_sha256_update,
    -- ** Blake2b 256
    c_crypto_generichash,
    CryptoBlake2b256State,
    c_crypto_generichash_final,
    c_crypto_generichash_init,
    c_crypto_generichash_update,
    -- * Helpers
    c_sodium_compare,
    -- * Constants
    CRYPTO_SHA256_BYTES,
    CRYPTO_SHA512_BYTES,
    CRYPTO_BLAKE2B_256_BYTES,
    CRYPTO_SHA256_STATE_SIZE,
    CRYPTO_SHA512_STATE_SIZE,
    CRYPTO_BLAKE2B_256_STATE_SIZE,
    ) where

import Foreign.C.Types
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.Storable (Storable)

import Cardano.Crypto.Libsodium.Constants
import Cardano.Crypto.FiniteBytes

-------------------------------------------------------------------------------
-- Initialization
-------------------------------------------------------------------------------

-- | @void sodium_init();@
--
-- <https://libsodium.gitbook.io/doc/usage>
foreign import capi "sodium.h sodium_init"  c_sodium_init :: IO Int

-------------------------------------------------------------------------------
-- Memory management
-------------------------------------------------------------------------------

-- | @void sodium_memzero(void * const pnt, const size_t len);@
--
-- <https://libsodium.gitbook.io/doc/memory_management#zeroing-memory>
foreign import capi "sodium.h sodium_memzero" c_sodium_memzero :: Ptr a -> CSize -> IO ()

-- | @void *sodium_malloc(size_t size);@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi "sodium.h sodium_malloc" c_sodium_malloc :: CSize -> IO (Ptr a)
--
-- | @void sodium_free(void *ptr);@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi "sodium.h sodium_free" c_sodium_free :: Ptr a -> IO ()

-- | @void sodium_free(void *ptr);@
--
-- <https://libsodium.gitbook.io/doc/memory_management>
foreign import capi "sodium.h &sodium_free" c_sodium_free_funptr :: FunPtr (Ptr a -> IO ())

-------------------------------------------------------------------------------
-- Hashing: SHA256
-------------------------------------------------------------------------------

-- | @int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);@
--
-- <https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function>
foreign import capi "sodium.h crypto_hash_sha256" c_crypto_hash_sha256 :: Ptr (FiniteBytes CRYPTO_SHA256_BYTES) -> Ptr CUChar -> CULLong -> IO Int

newtype CryptoSha256State = CryptoSha256State (FiniteBytes CRYPTO_SHA256_STATE_SIZE)
  deriving newtype Storable

-- | @int crypto_hash_sha256_init(crypto_hash_sha256_state *state);@
foreign import capi "sodium.h crypto_hash_sha256_init" c_crypto_hash_sha256_init :: Ptr CryptoSha256State -> IO Int

-- | @int crypto_hash_sha256_update(crypto_hash_sha256_state *state, const unsigned char *in, unsigned long long inlen);@
foreign import capi "sodium.h crypto_hash_sha256_update" c_crypto_hash_sha256_update :: Ptr CryptoSha256State -> Ptr CUChar -> CULLong -> IO Int

-- | @int crypto_hash_sha256_final(crypto_hash_sha256_state *state, unsigned char *out);@
foreign import capi "sodium.h crypto_hash_sha256_final" c_crypto_hash_sha256_final :: Ptr CryptoSha256State -> Ptr (FiniteBytes CRYPTO_SHA256_BYTES) -> IO Int

-------------------------------------------------------------------------------
-- Hashing: Blake2b
-------------------------------------------------------------------------------

-- | @int crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen);@
--
-- <https://libsodium.gitbook.io/doc/hashing/generic_hashing>
foreign import capi "sodium.h crypto_generichash" c_crypto_generichash
    :: Ptr out -> CSize
    -> Ptr CUChar -> CULLong
    -> Ptr key -> CSize
    -> IO Int

newtype CryptoBlake2b256State = CryptoBlake2b256State (FiniteBytes CRYPTO_BLAKE2B_256_STATE_SIZE)
  deriving newtype Storable

-- | @int crypto_generichash_init(crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen);@
foreign import capi "sodium.h crypto_generichash_init" c_crypto_generichash_init :: Ptr CryptoSha256State -> Ptr key -> CSize -> CSize -> IO Int

-- | @int crypto_generichash_update(crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen);@
foreign import capi "sodium.h crypto_generichash_update" c_crypto_generichash_update :: Ptr CryptoSha256State -> Ptr CUChar -> CULLong -> IO Int

-- | @int crypto_generichash_final(crypto_generichash_state *state, unsigned char *out, const size_t outlen);@
foreign import capi "sodium.h crypto_generichash_final" c_crypto_generichash_final :: Ptr CryptoSha256State -> Ptr out -> CSize -> IO Int

-------------------------------------------------------------------------------
-- Helpers
-------------------------------------------------------------------------------

-- | @int sodium_compare(const void * const b1_, const void * const b2_, size_t len);@
--
-- <https://libsodium.gitbook.io/doc/helpers#comparing-large-numbers>
foreign import capi "sodium.h sodium_compare" c_sodium_compare :: Ptr a -> Ptr a -> CSize -> IO Int
