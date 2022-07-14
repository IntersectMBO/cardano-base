{-# LANGUAGE DataKinds #-}
module Cardano.Crypto.SECP256K1.Constants (
    SECP256K1_PUBKEY_BYTES,
    SECP256K1_PRIVKEY_BYTES,
    SECP256K1_XONLY_PUBKEY_BYTES,
    SECP256K1_KEYPAIR_BYTES,
    SECP256K1_SCHNORR_SIGNATURE_BYTES
    )  where

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

-- Not defined as a struct, but derived from inspecting the source
type SECP256K1_PRIVKEY_BYTES = 32
type SECP256K1_PUBKEY_BYTES = 32
type SECP256K1_XONLY_PUBKEY_BYTES = #{size secp256k1_xonly_pubkey}
type SECP256K1_KEYPAIR_BYTES = #{size secp256k1_keypair}
-- Not defined as a struct, but derived from inspecting the source
type SECP256K1_SCHNORR_SIGNATURE_BYTES = 64
