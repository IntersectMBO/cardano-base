#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sodium/crypto_hash_sha512.h"
#include "crypto_vrf_ietfdraft13.h"
#include "sodium/crypto_core_ed25519.h"
#include "../private/ed25519_ref10.h"
#include "vrf_ietfdraft13.h"
#include "sodium/crypto_verify_16.h"
#include "sodium/randombytes.h"

static int
vrf_proof_to_hash(unsigned char *beta,
                  const unsigned char *pi,
                  const int batch)
{
    ge25519_p3    Gamma;
    unsigned char gamma_string[32];
    unsigned long pi_len;

    if (batch == 1) {pi_len = 128;} else {pi_len = 80;}

    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    if (pi[pi_len - 1] & 240 &&
        sc25519_is_canonical(pi + (pi_len - 32)) == 0) {
        return -1;
    }

    ge25519_clear_cofactor(&Gamma);
    ge25519_p3_tobytes(gamma_string, &Gamma);

    /* beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma) || zero_string ) */
    crypto_hash_sha512_state hs;
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &THREE, 1);
    crypto_hash_sha512_update(&hs, gamma_string, 32);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, beta);

    return 0;
}

int
crypto_vrf_ietfdraft13_proof_to_hash(unsigned char *beta,
                                     const unsigned char *pi)
{
    return vrf_proof_to_hash(beta, pi, 0);
}

int
crypto_vrf_ietfdraft13_proof_to_hash_batchcompat(unsigned char *beta,
                                                 const unsigned char *pi)
{
    return vrf_proof_to_hash(beta, pi, 1);
}

static int
vrf_verify(const unsigned char *pi,
           const unsigned char *alpha, unsigned long long alphalen,
           const ge25519_p3 *Y_point)
{
    unsigned char H_string[32], U_string[32], V_string[32], Y_string[32];
    unsigned char cn[32], c[32], s[32];
    unsigned char hram[64];
    unsigned char *string_to_hash = malloc((32 + alphalen) * sizeof(char));

    crypto_hash_sha512_state hs;
    ge25519_p2     U, V;
    ge25519_p3     H, Gamma;
    ge25519_p1p1   tmp_p1p1_point;
    ge25519_cached tmp_cached_point;

    ge25519_p3_tobytes(Y_string, Y_point);

    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    memmove(c, pi+32, 16); /* c = pi[32:48] */
    memmove(s, pi+48, 32); /* s = pi[48:80] */

    if (s[31] & 240 &&
        sc25519_is_canonical(s) == 0) {
        return -1;
    }

    memset(c+16, 0, 16);

    if (string_to_hash == NULL) {
        return -1;
    }
    memmove(string_to_hash, Y_string, 32);
    memmove(string_to_hash + 32, alpha, alphalen);
    crypto_core_ed25519_from_string(H_string, "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\4", string_to_hash, 32 + alphalen, 2); /* elligator2 */


    ge25519_frombytes(&H, H_string);
    crypto_core_ed25519_scalar_negate(cn, c); /* negate scalar c */

    ge25519_double_scalarmult_vartime(&U, cn, Y_point, s);

    ge25519_double_scalarmult_vartime_variable(&V, cn, &Gamma, s, &H);

    ge25519_tobytes(U_string, &U);
    ge25519_tobytes(V_string, &V);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, Y_string, 32);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_update(&hs, pi, 32);
    crypto_hash_sha512_update(&hs, U_string, 32);
    crypto_hash_sha512_update(&hs, V_string, 32);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, hram);

    return crypto_verify_16(c, hram);
}

int
crypto_vrf_ietfdraft13_verify(unsigned char *output,
                              const unsigned char *pk,
                              const unsigned char *proof,
                              const unsigned char *msg, const unsigned long long msglen)
{
    ge25519_p3 Y;
    if (ge25519_has_small_order(pk) == 0 && ge25519_is_canonical(pk) == 1 &&
        ge25519_frombytes(&Y, pk) == 0 && (vrf_verify(proof, msg, msglen, &Y) == 0)) {
        return crypto_vrf_ietfdraft13_proof_to_hash(output, proof);
    } else {
        return -1;
    }
}

static int
vrf_verify_batchcompat(const unsigned char *pi,
                       const unsigned char *alpha, unsigned long long alphalen,
                       const ge25519_p3 *Y_point)
{
    unsigned char H_string[32], U_string[32], V_string[32], Y_string[32];
    unsigned char cn[32], c[32], s[32];
    unsigned char hram[64];
    unsigned char *string_to_hash = malloc((32 + alphalen) * sizeof(char));

    crypto_hash_sha512_state hs;
    ge25519_p2     U, V;
    ge25519_p3     H, Gamma;
    ge25519_p1p1   tmp_p1p1_point;
    ge25519_cached tmp_cached_point;

    ge25519_p3_tobytes(Y_string, Y_point);

    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    if (string_to_hash == NULL) {
        return -1;
    }

    memmove(string_to_hash, Y_string, 32);
    memmove(string_to_hash + 32, alpha, alphalen);
    crypto_core_ed25519_from_string(H_string, "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\4", string_to_hash, 32 + alphalen, 2); /* elligator2 */


    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, Y_string, 32);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_update(&hs, pi, 32);
    crypto_hash_sha512_update(&hs, pi + 32, 32);
    crypto_hash_sha512_update(&hs, pi + 64, 32);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, hram);

    memmove(c, hram, 16);
    memmove(s, pi+96, 32); /* s = pi[96:128] */

    if (s[31] & 240 &&
        sc25519_is_canonical(s) == 0) {
        return -1;
    }

    memset(c+16, 0, 16);

    ge25519_frombytes(&H, H_string);
    crypto_core_ed25519_scalar_negate(cn, c); /* negate scalar c todo: maybe negating a point is more efficient than a scalar*/

    ge25519_double_scalarmult_vartime(&U, cn, Y_point, s);

    ge25519_double_scalarmult_vartime_variable(&V, cn, &Gamma, s, &H);

    ge25519_tobytes(U_string, &U);
    ge25519_tobytes(V_string, &V);

    for (int i = 0; i<crypto_core_ed25519_BYTES; i++) {
        if (U_string[i] != pi[32 + i] || V_string[i] != pi[64 + i]) {
            return -1;
        }
    }
    return 0;
}

int
crypto_vrf_ietfdraft13_verify_batchcompat(unsigned char *output,
                                          const unsigned char *pk,
                                          const unsigned char *proof,
                                          const unsigned char *msg, const unsigned long long msglen)
{
    ge25519_p3 Y;
    if (ge25519_has_small_order(pk) == 0 && ge25519_is_canonical(pk) == 1 &&
        ge25519_frombytes(&Y, pk) == 0 && (vrf_verify_batchcompat(proof, msg, msglen, &Y) == 0)) {
        return crypto_vrf_ietfdraft13_proof_to_hash_batchcompat(output, proof);
    } else {
        return -1;
    }
}

//
// Batch verification, using Pippenger's algorithm as described in
// https://github.com/dalek-cryptography/curve25519-dalek/blob/main/src/backend/serial/scalar_mul/pippenger.rs
//

#define MAX_BATCH_SIZE 1024
#define HEAP_BATCH_SIZE ((MAX_BATCH_SIZE * 5) + 1)

// we need to get the 2^w representation of a scalar.
static void
to_radix_2w(signed char *r, const unsigned char *a, unsigned char w)
{
    if (w != 6 && w != 7 && w != 8) {
        // This should never happen
        abort();
    }
    unsigned long scalar64x4[4];
    unsigned long radix = 1 << w;
    unsigned long window_mask = radix - 1;
    unsigned long carry = 0;
    unsigned long digits_count = (256 + w - 1)/w;
    int i;

    memcpy(scalar64x4, a, 32);

    for (i = 0; i < digits_count; i++) {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        int bit_offset = i * w;
        int u64_idx = bit_offset / 64;
        int bit_idx = bit_offset % 64;
        unsigned long long coef;

        // Read the bits from the scalar
        unsigned long long bit_buf;
        if (bit_idx < 64 - w || u64_idx == 3) {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            bit_buf = scalar64x4[u64_idx] >> bit_idx;
        } else {
            // Combine the current u64's bits with the bits from the next u64
            bit_buf = (scalar64x4[u64_idx] >> bit_idx) | (scalar64x4[1 + u64_idx] << (64 - bit_idx));
        }

        // Read the actual coefficient value from the window
        coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + (radix / 2)) >> w;
        r[i] = coef - (carry << w);
    }

    switch (w) {
        case 8:
            r[digits_count] += carry;
        default:
            r[digits_count-1] += (carry << w);
    }
}

typedef struct batch_heap_t {
    ge25519_cached points[HEAP_BATCH_SIZE];
    unsigned char scalars[HEAP_BATCH_SIZE][32];
} batch_heap;

static void double_w_times(ge25519_p3 *point, char w) {
    ge25519_p1p1 temp_p1;
    ge25519_p2 temp_p2;

    if (w == 0) {
        return;
    }

    ge25519_p3_dbl(&temp_p1, point);
    // double w - 1 times
    for (int i = 0; i < w - 1; i++) {
        ge25519_p1p1_to_p2(&temp_p2, &temp_p1);
        ge25519_p2_dbl(&temp_p1, &temp_p2);
    }
    ge25519_p1p1_to_p3(point, &temp_p1);
}

static int ge25519_multi_scalarmult_vartime(ge25519_p3 *r, batch_heap *heap, size_t count) {
    unsigned long w;
    unsigned long max_digit;
    unsigned long digit_count;
    unsigned long buckets_count;
    signed char** digits = malloc(sizeof(char*) * count);
    ge25519_p3* buckets;
    ge25519_p3 temp_bucket_sum;
    ge25519_p3 temp_p3;
    ge25519_p1p1 temp_p1;
    ge25519_cached buckets_sum;
    ge25519_cached res_cached;
    int i, j;

    if (digits == NULL) {
        return -1;
    }

    if (count < 500) {
        w = 6;
    } else if (count < 800) {
        w = 7;
    } else {
        w = 8;
    }

    max_digit = 1 << w;
    digit_count = (256 + w - 1)/w;
    buckets_count = max_digit / 2;
    buckets = malloc(sizeof(ge25519_p3) * buckets_count);

    if (buckets == NULL) {
        return -1;
    }

    // initialise the result as the identity element
    fe25519_0(r->X);
    fe25519_1(r->Y);
    fe25519_1(r->Z);
    fe25519_0(r->T);

    ge25519_p3_to_cached(&res_cached, r);
    // Get the 2^w radix representation
    for (i = 1; i < count; i++) {
        digits[i] = malloc(sizeof(char) * digit_count);
        if (digits[i] == NULL) {
            return -1;
        }
        to_radix_2w(digits[i], heap->scalars[i], w);
    }

    for (i = digit_count - 1; i >= 0; i--) {
        // Set all buckets to the identity
        for (j = 0; j < buckets_count; j++) {
            fe25519_0(buckets[j].X);
            fe25519_1(buckets[j].Y);
            fe25519_1(buckets[j].Z);
            fe25519_0(buckets[j].T);
        }

        for (j = 1; j < count; j++) {
            signed char digit = digits[j][i];
            if (digit > 0) {
                unsigned char b = digit - 1;
                ge25519_add(&temp_p1, &buckets[b], &heap->points[j]);
                ge25519_p1p1_to_p3(&buckets[b], &temp_p1);
            } else if (digit < 0) {
                unsigned char b = (- digit - 1);
                ge25519_sub(&temp_p1, &buckets[b], &heap->points[j]);
                ge25519_p1p1_to_p3(&buckets[b], &temp_p1);
            }
        }

        temp_bucket_sum = buckets[buckets_count - 1];
        ge25519_p3_to_cached(&buckets_sum, &buckets[buckets_count - 1]);
        /*
         * s1 + 2*s2 + 3*s3 + ... + buckets_count * sbuckets_count = s3 + (s3 + s2) + (s3 + s2 + s1) + ..
         */
        for (j = buckets_count - 2; j >= 0; j--) {
            ge25519_cached temp_cached;

            ge25519_p3_to_cached(&temp_cached, &buckets[j]);
            ge25519_add(&temp_p1, &temp_bucket_sum, &temp_cached);
            ge25519_p1p1_to_p3(&temp_bucket_sum, &temp_p1);
            ge25519_add(&temp_p1, &temp_bucket_sum, &buckets_sum);
            ge25519_p1p1_to_p3(&temp_p3, &temp_p1);
            ge25519_p3_to_cached(&buckets_sum, &temp_p3);
        }

        ge25519_add(&temp_p1, &temp_p3, &res_cached);
        ge25519_p1p1_to_p3(&temp_p3, &temp_p1);
        // the last bucket, we don't need to double.
        if (i != 0) {
            double_w_times(&temp_p3, w);
        }

        ge25519_p3_to_cached(&res_cached, &temp_p3);
    }
    ge25519_scalarmult_base(&temp_p3, heap->scalars[0]);
    ge25519_add(&temp_p1, &temp_p3, &res_cached);
    ge25519_p1p1_to_p3(r, &temp_p1);

    return 0;
}

static int is_identity(const ge25519_p3 *point) {
    unsigned char bytes[32];
    ge25519_p3_tobytes(bytes, point);

    if (bytes[0] != 1) {
        return -1;
    }

    for (int j = 1; j < 32; j++) {
        if (bytes[j] != 0) {
            return -1;
        }
    }

    return 0;
}

int
crypto_vrf_ietfdraft13_batch_verify(unsigned char *output[64],
                                    const unsigned char *pk[32],
                                    const unsigned char *proof[128],
                                    const unsigned char **msg,
                                    const unsigned long long *msglen,
                                    size_t num)
{
    batch_heap batch;

    unsigned char** challenges = malloc(sizeof(char*) * num);

    ge25519_p3 result;
    ge25519_p3 non_cached_points[5];

    if (challenges == NULL) {
        return -1;
    }

    // initialise the factor of the base point as zero.
    memset(batch.scalars[0], 0, 32);
    for (int i = 0; i < num; i++) {
        if (ge25519_has_small_order(pk[i]) == 0 && ge25519_is_canonical(pk[i]) == 1 &&
            ge25519_is_canonical(proof[i]) == 1 && ge25519_is_canonical(proof[i] + 32) == 1 &&
            ge25519_is_canonical(proof[i] + 64) == 1 && !(proof[i][31] & 240 && sc25519_is_canonical(proof[i] + 96) == 0) &&
            ge25519_frombytes_negate_vartime(&non_cached_points[0], pk[i]) == 0 &&
            ge25519_frombytes_negate_vartime(&non_cached_points[1], proof[i] + 32) == 0 &&
            ge25519_frombytes_negate_vartime(&non_cached_points[3], proof[i]) == 0 &&
            ge25519_frombytes_negate_vartime(&non_cached_points[4], proof[i] + 64) == 0)
        {
            unsigned char challenge[64], H_string[32];
            unsigned char *string_to_hash = malloc((32 + msglen[i]) * sizeof(char));

            ge25519_p3 temp_p3;
            ge25519_p1p1 temp_p1;
            ge25519_cached temp_cached;

            crypto_hash_sha512_state hs;

            challenges[i] = malloc(sizeof(char) * 32);
            if (challenges[i] == NULL || string_to_hash == NULL) {
                return -1;
            }

            memmove(string_to_hash, pk[i], 32);
            memmove(string_to_hash + 32, msg[i], msglen[i]);
            crypto_core_ed25519_from_string(H_string, "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\4", string_to_hash, 32 + msglen[i], 2); /* elligator2 */

            crypto_hash_sha512_init(&hs);
            crypto_hash_sha512_update(&hs, &SUITE, 1);
            crypto_hash_sha512_update(&hs, &TWO, 1);
            crypto_hash_sha512_update(&hs, pk[i], 32);
            crypto_hash_sha512_update(&hs, H_string, 32);
            crypto_hash_sha512_update(&hs, proof[i], 32);
            crypto_hash_sha512_update(&hs, proof[i] + 32, 32);
            crypto_hash_sha512_update(&hs, proof[i] + 64, 32);
            crypto_hash_sha512_update(&hs, &ZERO, 1);
            crypto_hash_sha512_final(&hs, challenge);

            memset(challenges[i], 0, 32);
            memmove(challenges[i], challenge, 16);

            ge25519_frombytes(&non_cached_points[2], H_string);

            ge25519_p3_to_cached(&batch.points[5 * i + 1], &non_cached_points[0]); // - pk
            ge25519_p3_to_cached(&batch.points[5 * i + 2], &non_cached_points[1]); // - U
            ge25519_p3_to_cached(&batch.points[5 * i + 3], &non_cached_points[2]); // H
            ge25519_p3_to_cached(&batch.points[5 * i + 4], &non_cached_points[3]); // - Gamma
            ge25519_p3_to_cached(&batch.points[5 * i + 5], &non_cached_points[4]); // - V

            unsigned char l[32] = {1};
            unsigned char r[32] = {1};

            randombytes_buf(l, 16);
            randombytes_buf(r, 16);

            // sum of ri si
            /* compute  r0s0 + r1s1 + r2s2, ...) */
            sc25519_muladd(batch.scalars[0], proof[i] + 96, r, batch.scalars[0]);

            // now we include the scalar mults in the following order (must follow the
            // corresponding order wrt the points above):
            sc25519_mul(batch.scalars[5 * i + 1], r, challenges[i]);
            memcpy(batch.scalars[5 * i + 2], r, 32);
            sc25519_mul(batch.scalars[5 * i + 3], l, proof[i]+96);
            sc25519_mul(batch.scalars[5 * i + 4], l, challenges[i]);
            memcpy(batch.scalars[5 * i + 5], l, 32);
        } else {
            return -1;
        }
    }

    if (ge25519_multi_scalarmult_vartime(&result, &batch, num * 5 + 1) != 0) {
        return -1;
    }

    if (is_identity(&result) != 0) {
        return -1;
    }

    for (int i = 0; i < num; i++) {
        if (crypto_vrf_ietfdraft13_proof_to_hash_batchcompat(output[i], proof[i]) != 0) {
            return -1;
        }
    }

    return 0;
}
