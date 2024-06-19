{-# LINE 1 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
{-# LANGUAGE DataKinds #-}
module Cardano.Crypto.Libsodium.Constants (
    CRYPTO_SHA256_BYTES,
    CRYPTO_SHA512_BYTES,
    CRYPTO_BLAKE2B_256_BYTES,
    CRYPTO_SHA256_STATE_SIZE,
    CRYPTO_SHA512_STATE_SIZE,
    CRYPTO_BLAKE2B_256_STATE_SIZE,
    CRYPTO_SIGN_ED25519_BYTES,
    CRYPTO_SIGN_ED25519_SEEDBYTES,
    CRYPTO_SIGN_ED25519_PUBLICKEYBYTES,
    CRYPTO_SIGN_ED25519_SECRETKEYBYTES,
    )  where



-- From https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function
-- and https://libsodium.gitbook.io/doc/hashing/generic_hashing

type CRYPTO_SHA256_BYTES = 32
{-# LINE 21 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
type CRYPTO_SHA512_BYTES = 64
{-# LINE 22 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
type CRYPTO_BLAKE2B_256_BYTES = 32
{-# LINE 23 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}

type CRYPTO_SHA256_STATE_SIZE = (104)
{-# LINE 25 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
type CRYPTO_SHA512_STATE_SIZE = (208)
{-# LINE 26 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
type CRYPTO_BLAKE2B_256_STATE_SIZE = (384)
{-# LINE 27 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}

type CRYPTO_SIGN_ED25519_BYTES = 64
{-# LINE 29 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
type CRYPTO_SIGN_ED25519_SEEDBYTES = 32
{-# LINE 30 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
type CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32
{-# LINE 31 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
type CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64
{-# LINE 32 "src/Cardano/Crypto/Libsodium/Constants.hsc" #-}
