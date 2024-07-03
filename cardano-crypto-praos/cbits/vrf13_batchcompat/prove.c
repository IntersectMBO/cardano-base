#include <string.h>
#include <stdlib.h>

#include "sodium/crypto_hash_sha512.h"
#include "crypto_vrf_ietfdraft13.h"
#include "sodium/crypto_core_ed25519.h"
#include "../private/ed25519_ref10.h"
#include "sodium/utils.h"
#include "../crypto_vrf.h"


int
crypto_vrf_ietfdraft13_prove(unsigned char *proof, const unsigned char *skpk,
                             const unsigned char *m, unsigned long long mlen)
{

    crypto_hash_sha512_state hs;
    unsigned char az[64];
    unsigned char H_string[32];
    unsigned char kB_string[32], kH_string[32];
    unsigned char *string_to_hash = malloc((32 + mlen) * sizeof(char));
    unsigned char hram[64], nonce[64];
    ge25519_p3    H, Gamma, kB, kH;

    crypto_hash_sha512(az, skpk, 32);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;

    if (string_to_hash == NULL) {
        return -1;
    }

    memmove(string_to_hash, skpk + 32, 32);
    memmove(string_to_hash + 32, m, mlen);
    cardano_crypto_core_ed25519_from_string(H_string, "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\4", string_to_hash, 32 + mlen, 2); /* elligator2 */

    cardano_ge25519_frombytes(&H, H_string);
    cardano_ge25519_scalarmult(&Gamma, az, &H);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, az + 32, 32);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_final(&hs, nonce);

    cardano_sc25519_reduce(nonce);
    cardano_ge25519_scalarmult_base(&kB, nonce);
    cardano_ge25519_scalarmult(&kH, nonce, &H);

    cardano_ge25519_p3_tobytes(proof, &Gamma);
    cardano_ge25519_p3_tobytes(kB_string, &kB);
    cardano_ge25519_p3_tobytes(kH_string, &kH);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, skpk + 32, 32);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_update(&hs, proof, 32);
    crypto_hash_sha512_update(&hs, kB_string, 32);
    crypto_hash_sha512_update(&hs, kH_string, 32);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, hram);

    memmove(proof + 32, hram, 16);
    memset(hram + 16, 0, 48); /* we zero out the last 48 bytes of the challenge */
    cardano_sc25519_muladd(proof + 48, hram, az, nonce);

    sodium_memzero(az, sizeof az);
    sodium_memzero(nonce, sizeof nonce);

    return 0;
}

int
crypto_vrf_ietfdraft13_prove_batchcompat(unsigned char *proof, const unsigned char *skpk,
                                         const unsigned char *m, unsigned long long mlen)
{

    crypto_hash_sha512_state hs;
    unsigned char az[64];
    unsigned char H_string[32];
    unsigned char kB_string[32], kH_string[32];
    unsigned char *string_to_hash = malloc((32 + mlen) * sizeof(char));
    unsigned char hram[64], nonce[64];
    ge25519_p3    H, Gamma, kB, kH;

    crypto_hash_sha512(az, skpk, 32);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;

    if (string_to_hash == NULL) {
        return -1;
    }

    memmove(string_to_hash, skpk + 32, 32);
    memmove(string_to_hash + 32, m, mlen);
    cardano_crypto_core_ed25519_from_string(H_string, "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\4", string_to_hash, 32 + mlen, 2); /* elligator2 */

    cardano_ge25519_frombytes(&H, H_string);
    cardano_ge25519_scalarmult(&Gamma, az, &H);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, az + 32, 32);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_final(&hs, nonce);

    cardano_sc25519_reduce(nonce);
    cardano_ge25519_scalarmult_base(&kB, nonce);
    cardano_ge25519_scalarmult(&kH, nonce, &H);

    cardano_ge25519_p3_tobytes(proof, &Gamma);
    cardano_ge25519_p3_tobytes(kB_string, &kB);
    cardano_ge25519_p3_tobytes(kH_string, &kH);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, skpk + 32, 32);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_update(&hs, proof, 32);
    crypto_hash_sha512_update(&hs, kB_string, 32);
    crypto_hash_sha512_update(&hs, kH_string, 32);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, hram);

    memmove(proof + 32, kB_string, 32);
    memmove(proof + 64, kH_string, 32);
    memset(hram + 16, 0, 48); /* we zero out the last 48 bytes of the challenge */
    cardano_sc25519_muladd(proof + 96, hram, az, nonce);

    sodium_memzero(az, sizeof az);
    sodium_memzero(nonce, sizeof nonce);

    return 0;
}
