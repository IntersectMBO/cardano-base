#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sodium/crypto_hash_sha512.h"
#include "crypto_vrf_ietfdraft03.h"
#include "sodium/crypto_core_ed25519.h"
#include "../private/ed25519_ref10.h"
#include "../crypto_vrf.h"
#include "sodium/crypto_verify_16.h"

int
crypto_vrf_ietfdraft03_proof_to_hash(unsigned char *beta,
                                     const unsigned char *pi)
{
    ge25519_p3    Gamma;
    unsigned char gamma_string[32];

    if (cardano_ge25519_is_canonical(pi) == 0 ||
        cardano_ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    if (pi[48 + 31] & 240 &&
        cardano_sc25519_is_canonical(pi + 48) == 0) {
        return -1;
    }

    cardano_ge25519_clear_cofactor(&Gamma);
    cardano_ge25519_p3_tobytes(gamma_string, &Gamma);

    /* beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma) || zero_string ) */
    crypto_hash_sha512_state hs;
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &THREE, 1);
    crypto_hash_sha512_update(&hs, gamma_string, 32);
    crypto_hash_sha512_final(&hs, beta);

    return 0;
}

static int
vrf_verify(const unsigned char *pi,
           const unsigned char *alpha, unsigned long long alphalen,
           const ge25519_p3 *Y_point)
{
    unsigned char H_string[32], U_string[32], V_string[32], Y_string[32];
    unsigned char cn[32], c[32], s[32];
    unsigned char hram[64], r_string[64];

    crypto_hash_sha512_state hs;
    ge25519_p2     U, V;
    ge25519_p3     H, Gamma;
    ge25519_p1p1   tmp_p1p1_point;
    ge25519_cached tmp_cached_point;

    cardano_ge25519_p3_tobytes(Y_string, Y_point);

    if (cardano_ge25519_is_canonical(pi) == 0 ||
        cardano_ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    memmove(c, pi+32, 16); /* c = pi[32:48] */
    memmove(s, pi+48, 32); /* s = pi[48:80] */

    if (s[31] & 240 &&
        cardano_sc25519_is_canonical(s) == 0) {
        return -1;
    }

    memset(c+16, 0, 16);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &ONE, 1);
    crypto_hash_sha512_update(&hs, Y_string, 32);
    crypto_hash_sha512_update(&hs, alpha, alphalen);
    crypto_hash_sha512_final(&hs, r_string);

    r_string[31] &= 0x7f; /* clear sign bit */
    cardano_ge25519_from_uniform(H_string, r_string); /* elligator2 */

    cardano_ge25519_frombytes(&H, H_string);
    crypto_core_ed25519_scalar_negate(cn, c); /* negate scalar c */

    cardano_ge25519_double_scalarmult_vartime(&U, cn, Y_point, s);

    cardano_ge25519_double_scalarmult_vartime_variable(&V, cn, &Gamma, s, &H);

    cardano_ge25519_tobytes(U_string, &U);
    cardano_ge25519_tobytes(V_string, &V);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_update(&hs, pi, 32);
    crypto_hash_sha512_update(&hs, U_string, 32);
    crypto_hash_sha512_update(&hs, V_string, 32);
    crypto_hash_sha512_final(&hs, hram);

    return crypto_verify_16(c, hram);
}

int
crypto_vrf_ietfdraft03_verify(unsigned char *output,
                              const unsigned char *pk,
                              const unsigned char *proof,
                              const unsigned char *msg, const unsigned long long msglen)
{
    ge25519_p3 Y;
    if (cardano_ge25519_has_small_order(pk) == 0 && cardano_ge25519_is_canonical(pk) == 1 &&
        cardano_ge25519_frombytes(&Y, pk) == 0 && (vrf_verify(proof, msg, msglen, &Y) == 0)) {
        return crypto_vrf_ietfdraft03_proof_to_hash(output, proof);
    } else {
        return -1;
    }
}
