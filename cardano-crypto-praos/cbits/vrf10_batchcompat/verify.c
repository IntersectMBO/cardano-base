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

#include "sodium/crypto_hash_sha512.h"
#include "crypto_vrf_ietfdraft10.h"
#include "sodium/crypto_core_ed25519.h"
#include "../private/ed25519_ref10.h"
#include "vrf_ietfdraft10.h"

static const unsigned char ZERO = 0x00;
static const unsigned char THREE = 0x03;

/* Utility function to multiply a point by the cofactor (8) in place. */
static void
multiply_by_cofactor(ge25519_p3 *point) {
    ge25519_cached tmp_point;
    ge25519_p1p1   tmp2_point;

    ge25519_p3_to_cached(&tmp_point, point);     /* tmp = input */
    ge25519_add(&tmp2_point, point, &tmp_point); /* tmp2 = 2*input */
    ge25519_p1p1_to_p3(point, &tmp2_point);      /* point = 2*input */
    ge25519_p3_to_cached(&tmp_point, point);     /* tmp = 2*input */
    ge25519_add(&tmp2_point, point, &tmp_point); /* tmp2 = 4*input */
    ge25519_p1p1_to_p3(point, &tmp2_point);      /* point = 4*input */
    ge25519_p3_to_cached(&tmp_point, point);     /* tmp = 4*input */
    ge25519_add(&tmp2_point, point, &tmp_point); /* tmp2 = 8*input */
    ge25519_p1p1_to_p3(point, &tmp2_point);      /* point = 8*input */
}

static void hash_gamma(unsigned char beta[crypto_vrf_ietfdraft10_OUTPUTBYTES], ge25519_p3 Gamma_point) {
    unsigned char gamma_string[crypto_core_ed25519_BYTES];

    multiply_by_cofactor(&Gamma_point);
    _vrf_ietfdraft10_point_to_string(gamma_string, &Gamma_point);

    /* beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma) || zero_string ) */
    crypto_hash_sha512_state hs;
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &THREE, 1);
    crypto_hash_sha512_update(&hs, gamma_string, crypto_core_ed25519_BYTES);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, beta);
}

/*
 * Convert a batch compatible VRF proof pi into a VRF output hash beta per draft spec section 5.2.
 * This function does not verify the proof! For an untrusted proof, instead call
 * crypto_vrf_ietfdraft10_verify, which will output the hash if verification
 * succeeds.
 * Returns 0 on success, -1 on failure decoding the proof.
 */
int
crypto_vrf_ietfdraft10_proof_to_hash_batchcompat(unsigned char beta[crypto_vrf_ietfdraft10_OUTPUTBYTES],
                                     const unsigned char pi[crypto_vrf_ietfdraft10_PROOFBYTES_BATCHCOMPAT])
{
    ge25519_p3    Gamma_point;
    unsigned char s_scalar[crypto_core_ed25519_SCALARBYTES];
    unsigned char gamma_string[crypto_core_ed25519_BYTES];

    unsigned char U_point[crypto_core_ed25519_BYTES], V_point[crypto_core_ed25519_BYTES];
    /* (Gamma, U, V, s) = ECVRF_decode_proof(pi_string) */
    if (_vrf_ietfdraft10_decode_proof_batchcompat(&Gamma_point, U_point, V_point, s_scalar, pi) != 0) {
        return -1;
    }

    hash_gamma(beta, Gamma_point);

    return 0;
}

/* Validate an untrusted public key as specified in the draft spec section
 * 5.6.1.
 *
 * This means check that it is not of low order and that it is canonically
 * encoded (i.e., y coordinate is already reduced mod p) Per the spec, we do not
 * check if the point is on the main subgroup.
 *
 * Returns 0 on success (and stores decoded curve point in y_out), -1 on
 * failure.
 */
static int
vrf_validate_key(ge25519_p3 *y_out, const unsigned char pk_string[crypto_vrf_ietfdraft10_PUBLICKEYBYTES])
{
    if (ge25519_has_small_order(pk_string) != 0 || _vrf_ietfdraft10_string_to_point(y_out, pk_string) != 0) {
        return -1;
    }
    return 0;
}

/* Validate an untrusted public key as specified in the draft spec section
 * 5.6.1. Return 1 if the key is valid, 0 otherwise.
 */
int
crypto_vrf_ietfdraft10_is_valid_key(const unsigned char pk[crypto_vrf_ietfdraft10_PUBLICKEYBYTES])
{
    ge25519_p3 point; /* unused */
    return (vrf_validate_key(&point, pk) == 0);
}

/* Verify a proof for batch compatible proofs. Return 0 on success, -1 on failure.
 * We assume Y_point has passed public key validation already.
 * Assuming verification succeeds, runtime does not depend on the message alpha
 * (but does depend on its length alphalen)
 */
static int
vrf_verify_batchcompat(const ge25519_p3 *Y_point, const unsigned char pi[crypto_vrf_ietfdraft10_PROOFBYTES_BATCHCOMPAT],
           const unsigned char *alpha, const unsigned long long alphalen)
{
    /* Note: c fits in 16 bytes, but ge25519_scalarmult expects a 32-byte scalar.*/
    unsigned char h_string[crypto_core_ed25519_BYTES], cn_scalar[crypto_core_ed25519_SCALARBYTES], c_scalar[crypto_core_ed25519_SCALARBYTES], s_scalar[crypto_core_ed25519_SCALARBYTES],
            U_bytes[crypto_core_ed25519_BYTES], V_bytes[crypto_core_ed25519_BYTES], expected_U_bytes[crypto_core_ed25519_BYTES], expected_V_bytes[crypto_core_ed25519_BYTES];

    ge25519_p2     U_point, V_point;
    ge25519_p3     H_point, Gamma_point, tmp_p3_point;
    ge25519_p1p1   tmp_p1p1_point;
    ge25519_cached tmp_cached_point;

    if (_vrf_ietfdraft10_decode_proof_batchcompat(&Gamma_point, expected_U_bytes, expected_V_bytes, s_scalar, pi) != 0) {
        return -1;
    }

#ifdef TRYANDINC
    /*
     * If try and increment fails after `TAI_NR_TRIES` tries, then we run elligator, to ensure that
     * the function runs correctly.
     */
    if (_vrf_ietfdraft10_hash_to_curve_try_inc(h_string, Y_point, alpha, alphalen) != 0) {
        _vrf_ietfdraft03_hash_to_curve_elligator2_25519(h_string, Y_point, alpha, alphalen);
    };
#else
    _vrf_ietfdraft10_hash_to_curve_elligator2_25519(h_string, Y_point, alpha, alphalen);
#endif
    ge25519_frombytes(&H_point, h_string);

    _vrf_ietfdraft10_hash_points(c_scalar, &H_point, &Gamma_point, expected_U_bytes, expected_V_bytes);
    /* vrf_decode_proof writes to the first 16 bytes of c_scalar; we zero the
     * second 16 bytes ourselves, as ge25519_scalarmult expects a 32-byte scalar.
     */
    memset(c_scalar+16, 0, 16);
    crypto_core_ed25519_scalar_negate(cn_scalar, c_scalar); /* negate scalar c */

    /* calculate U = s*B - c*Y */
    ge25519_double_scalarmult_vartime(&U_point, cn_scalar, Y_point, s_scalar);

    /* calculate V = s*H -  c*Gamma */
    ge25519_double_scalarmult_vartime_variable(&V_point, cn_scalar, &Gamma_point, s_scalar, &H_point);

    ge25519_tobytes(U_bytes, &U_point);
    ge25519_tobytes(V_bytes, &V_point);

    for (int i = 0; i<crypto_core_ed25519_BYTES; i++) {
        if (U_bytes[i] != expected_U_bytes[i] || V_bytes[i] != expected_V_bytes[i]) {
            return -1;
        }
    }
    return 0;
}

/* Verify a batch compatible VRF proof (for a given a public key and message) and validate the
 * public key. If verification succeeds, store the VRF output hash in output[].
 *
 * For a given public key and message, there are many possible proofs but only
 * one possible output hash.
 *
 * Returns 0 if verification succeeds (and stores output hash in output[]),
 * nonzero on failure.
 */
int
crypto_vrf_ietfdraft10_verify_batchcompat(unsigned char output[crypto_vrf_ietfdraft10_OUTPUTBYTES],
                              const unsigned char pk[crypto_vrf_ietfdraft10_PUBLICKEYBYTES],
                              const unsigned char proof[crypto_vrf_ietfdraft10_PROOFBYTES_BATCHCOMPAT],
                              const unsigned char *msg, const unsigned long long msglen)
{
    ge25519_p3 Y;
    if ((vrf_validate_key(&Y, pk) == 0) && (vrf_verify_batchcompat(&Y, proof, msg, msglen) == 0)) {
        return crypto_vrf_ietfdraft10_proof_to_hash_batchcompat(output, proof);
    } else {
        return -1;
    }
}
