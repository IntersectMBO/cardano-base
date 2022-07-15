{-# LANGUAGE DataKinds #-}
module Cardano.Crypto.SECP256K1.Constants (
    SECP256K1_ECDSA_PRIVKEY_BYTES,
    SECP256K1_ECDSA_SIGNATURE_BYTES,
    SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL,
    SECP256K1_ECDSA_PUBKEY_BYTES,
    SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL,
    SECP256K1_SCHNORR_PUBKEY_BYTES,
    SECP256K1_SCHNORR_PRIVKEY_BYTES,
    SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL,
    SECP256K1_SCHNORR_KEYPAIR_BYTES,
    SECP256K1_SCHNORR_SIGNATURE_BYTES
    )  where

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

-- ECDSA-related constants

type SECP256K1_ECDSA_PRIVKEY_BYTES = 32 
-- As we do not want to serialize the internal state used by ECDSA directly, we
-- define _two_ values: one for the 'external' representation size, and one for
-- the 'internal' representation size.
type SECP256K1_ECDSA_PUBKEY_BYTES = 33
type SECP256K1_ECDSA_PUBKEY_BYTES_INTERNAL = 64 
-- Same as here. They happen to be the same, but by using different tags, we can
-- ensure we don't mix them up on accident.
type SECP256K1_ECDSA_SIGNATURE_BYTES = 64
type SECP256K1_ECDSA_SIGNATURE_BYTES_INTERNAL = 64 

-- Schnorr-related constants

-- Not defined as a struct, but derived from inspecting the source
type SECP256K1_SCHNORR_PRIVKEY_BYTES = 32
-- As we do not want to serialize the internal state used by Schnorr directly,
-- we define _two_ values: one for the 'external' representation size, and one
-- for the 'internal' representation size.
type SECP256K1_SCHNORR_PUBKEY_BYTES = 32
type SECP256K1_SCHNORR_PUBKEY_BYTES_INTERNAL = #{size secp256k1_xonly_pubkey}
type SECP256K1_SCHNORR_KEYPAIR_BYTES = #{size secp256k1_keypair}
-- Not defined as a struct, but derived from inspecting the source
type SECP256K1_SCHNORR_SIGNATURE_BYTES = 64
