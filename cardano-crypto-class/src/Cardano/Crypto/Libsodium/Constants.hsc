{-# LANGUAGE DataKinds #-}
module Cardano.Crypto.Libsodium.Constants (
    CRYPTO_SHA256_BYTES,
    CRYPTO_SHA512_BYTES,
    CRYPTO_BLAKE2B_256_BYTES,
    CRYPTO_SHA256_STATE_SIZE,
    CRYPTO_SHA512_STATE_SIZE,
    CRYPTO_BLAKE2B_256_STATE_SIZE,
    )  where

#include <sodium.h>

-- From https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function
-- and https://libsodium.gitbook.io/doc/hashing/generic_hashing

type CRYPTO_SHA256_BYTES = #{const crypto_hash_sha256_BYTES}
type CRYPTO_SHA512_BYTES = #{const crypto_hash_sha512_BYTES}
type CRYPTO_BLAKE2B_256_BYTES = #{const crypto_generichash_BYTES}

type CRYPTO_SHA256_STATE_SIZE = #{size crypto_hash_sha256_state}
type CRYPTO_SHA512_STATE_SIZE = #{size crypto_hash_sha512_state}
type CRYPTO_BLAKE2B_256_STATE_SIZE = #{size crypto_generichash_state}


