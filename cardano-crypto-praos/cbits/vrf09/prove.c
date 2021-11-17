/*
Slight modification of document ./../ietfdraft03/convert.c to follow the
latest version of the standard, using the updated "Elligator2" hash_to_curve
function. We reproduce the copyright notice.
Copyright (c) 2018 Algorand LLC
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <string.h>
#include <stdlib.h>

#include "crypto_hash_sha512.h"
#include "crypto_vrf_ietfdraft09.h"
#include "private/ed25519_ref10.h"
#include "utils.h"
#include "vrf_ietfdraft09.h"

/* Utility function to convert a "secret key" (32-byte seed || 32-byte PK)
 * into the public point Y, the private saclar x, and truncated hash of the
 * seed to be used later in nonce generation.
 * Return 0 on success, -1 on failure decoding the public point Y.
 */
static int
vrf_expand_sk(ge25519_p3 *Y_point, unsigned char x_scalar[crypto_core_ed25519_SCALARBYTES],
              unsigned char truncated_hashed_sk_string[32], const unsigned char skpk[crypto_vrf_ietfdraft09_SECRETKEYBYTES])
{
    unsigned char h[crypto_hash_sha512_BYTES];

    crypto_hash_sha512(h, skpk, crypto_vrf_ietfdraft09_SEEDBYTES);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memmove(x_scalar, h, crypto_core_ed25519_SCALARBYTES);
    memmove(truncated_hashed_sk_string, h + crypto_core_ed25519_SCALARBYTES, 32);
    sodium_memzero(h, crypto_hash_sha512_BYTES);

    return _vrf_ietfdraft09_string_to_point(Y_point, skpk+crypto_vrf_ietfdraft09_SEEDBYTES);
}


/* Deterministically generate a (secret) nonce to be used in a proof.
 * Specified in draft spec section 5.4.2.2.
 * Note: In the spec, this subroutine computes truncated_hashed_sk_string
 * Here we instead takes it as an argument, and we compute it in vrf_expand_sk
 */
static void
vrf_nonce_generation(unsigned char k_scalar[crypto_core_ed25519_SCALARBYTES],
                     const unsigned char truncated_hashed_sk_string[32],
                     const unsigned char h_string[crypto_core_ed25519_BYTES])
{
    crypto_hash_sha512_state hs;
    unsigned char            k_string[crypto_hash_sha512_BYTES];

    /* k_string = SHA512(truncated_hashed_sk_string || h_string) */
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, truncated_hashed_sk_string, 32);
    crypto_hash_sha512_update(&hs, h_string, crypto_core_ed25519_BYTES);
    crypto_hash_sha512_final(&hs, k_string);

    sc25519_reduce(k_string); /* k_string[0:32] = string_to_int(k_string) mod q */
    memmove(k_scalar, k_string, crypto_core_ed25519_SCALARBYTES);

    sodium_memzero(k_string, sizeof k_string);
}

/* Construct a proof for a message alpha per draft spec section 5.1.
 * Takes in a secret scalar x, a public point Y, and a secret string
 * truncated_hashed_sk that is used in nonce generation.
 * These are computed from the secret key using the expand_sk function.
 * Constant time in everything except alphalen (the length of the message).
 *
 * The proof contains the two points U and V instead of the challenge
 * to allow for batch-verification.
 */
static void
vrf_prove(unsigned char pi[crypto_vrf_ietfdraft09_PROOFBYTES], const ge25519_p3 *Y_point,
          const unsigned char x_scalar[crypto_core_ed25519_SCALARBYTES],
          const unsigned char truncated_hashed_sk_string[32],
          const unsigned char *alpha, unsigned long long alphalen)
{
    /* c fits in 16 bytes, but we store it in a 32-byte array because
     * sc25519_muladd expects a 32-byte scalar */
    unsigned char h_string[crypto_core_ed25519_BYTES], k_scalar[crypto_core_ed25519_SCALARBYTES], c_scalar[crypto_core_ed25519_SCALARBYTES];
    ge25519_p3    H_point, Gamma_point, kB_point, kH_point;

#ifdef TRYANDINC
    /*
     * If try and increment fails after `TAI_NR_TRIES` tries, then we run elligator, to ensure that
     * the function runs correctly.
     */
    if (_vrf_ietfdraft09_hash_to_curve_try_inc(h_string, Y_point, alpha, alphalen) != 0) {
        _vrf_ietfdraft03_hash_to_curve_elligator2_25519(h_string, Y_point, alpha, alphalen);
    };
#else
    _vrf_ietfdraft09_hash_to_curve_elligator2_25519(h_string, Y_point, alpha, alphalen);
#endif
    ge25519_frombytes(&H_point, h_string);

    ge25519_scalarmult(&Gamma_point, x_scalar, &H_point); /* Gamma = x*H */
    vrf_nonce_generation(k_scalar, truncated_hashed_sk_string, h_string);
    ge25519_scalarmult_base(&kB_point, k_scalar); /* compute k*B */
    ge25519_scalarmult(&kH_point, k_scalar, &H_point); /* compute k*H */

    /* c = ECVRF_hash_points(h, gamma, k*B, k*H)
     * (writes only to the first 16 bytes of c_scalar)
     * We need to pass kB and kH to bytes for the new
     * function signature
     * */
    unsigned char kB_bytes[crypto_core_ed25519_BYTES], kH_bytes[crypto_core_ed25519_BYTES];
    ge25519_p3_tobytes(kB_bytes, &kB_point);
    ge25519_p3_tobytes(kH_bytes, &kH_point);

    _vrf_ietfdraft09_hash_points(c_scalar, &H_point, &Gamma_point, kB_bytes, kH_bytes);
    memset(c_scalar+16, 0, 16); /* zero the remaining 16 bytes of c_scalar */

    /* output pi */
    _vrf_ietfdraft09_point_to_string(pi, &Gamma_point); /* pi[0:32] = point_to_string(Gamma) */
    memmove(pi + crypto_core_ed25519_BYTES, kB_bytes, crypto_core_ed25519_BYTES); /* pi[32:64] = point_to_string(kB_point) */
    memmove(pi + (crypto_core_ed25519_BYTES * 2), kH_bytes, crypto_core_ed25519_BYTES); /* pi[64:96] = point_to_string(kH_point) */
    sc25519_muladd(pi + (crypto_core_ed25519_BYTES * 3), c_scalar, x_scalar, k_scalar); /* pi[96:128] = s = c*x + k (mod q) */

    sodium_memzero(k_scalar, sizeof k_scalar); /* k must remain secret */
    /* erase other non-sensitive intermediate state for good measure */
    sodium_memzero(h_string, sizeof h_string);
    sodium_memzero(c_scalar, sizeof c_scalar);
    sodium_memzero(&H_point, sizeof H_point);
    sodium_memzero(&Gamma_point, sizeof Gamma_point);
    sodium_memzero(&kB_point, sizeof kB_point);
    sodium_memzero(&kH_point, sizeof kH_point);
}

/* Construct a VRF proof given a secret key and a message.
 *
 * The "secret key" is 64 bytes long -- 32 byte secret seed concatenated
 * with 32 byte precomputed public key. Our keygen functions return secret keys
 * of this form.
 *
 * Returns 0 on success, nonzero on failure decoding the public key.
 *
 * Constant time in everything except msglen, unless decoding the public key
 * fails.
 */
int
crypto_vrf_ietfdraft09_prove(unsigned char proof[crypto_vrf_ietfdraft09_PROOFBYTES],
                             const unsigned char skpk[crypto_vrf_ietfdraft09_SECRETKEYBYTES],
                             const unsigned char *msg,
                             unsigned long long msglen)
{
    ge25519_p3    Y_point;
    unsigned char x_scalar[crypto_core_ed25519_SCALARBYTES], truncated_hashed_sk_string[32];

    if (vrf_expand_sk(&Y_point, x_scalar, truncated_hashed_sk_string, skpk) != 0) {
        sodium_memzero(x_scalar, crypto_core_ed25519_SCALARBYTES);
        sodium_memzero(truncated_hashed_sk_string, 32);
        sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
        return -1;
    }
    vrf_prove(proof, &Y_point, x_scalar, truncated_hashed_sk_string, msg, msglen);
    sodium_memzero(x_scalar, crypto_core_ed25519_SCALARBYTES);
    sodium_memzero(truncated_hashed_sk_string, 32);
    sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
    return 0;
}
