/*
This file implements the hash_to_curve required functions so that we
can run the latest version of libstodium stable, while leveraging the
latest version of Elligator2, as per the standard draft.
*/

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "sodium/crypto_core_ed25519.h"
#include "sodium/crypto_hash_sha512.h"
#include "common.h"
#include "ed25519_ref10.h"

#define HASH_GE_L 48U
#define HASH_BYTES      crypto_hash_sha512_BYTES
#define HASH_BLOCKBYTES 128U


static inline uint64_t
load_3(const unsigned char *in)
{
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;

    return result;
}

static inline uint64_t
load_4(const unsigned char *in)
{
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;

    return result;
}

#ifdef HAVE_TI_MODE
# include "fe_51/constants.h"
# include "fe_51/fe.h"
#else
# include "fe_25_5/constants.h"
# include "fe_25_5/fe.h"
#endif

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

static void
fe25519_reduce64(fe25519 fe_f, const unsigned char h[64])
{
    unsigned char fl[32];
    unsigned char gl[32];
    fe25519       fe_g;
    size_t        i;

    memcpy(fl, h, 32);
    memcpy(gl, h + 32, 32);
    fl[31] &= 0x7f;
    gl[31] &= 0x7f;
    fe25519_frombytes(fe_f, fl);
    fe25519_frombytes(fe_g, gl);
    fe_f[0] += (h[31] >> 7) * 19 + (h[63] >> 7) * 722;
    for (i = 0; i < sizeof (fe25519) / sizeof fe_f[0]; i++) {
        fe_f[i] += 38 * fe_g[i];
    }
    fe25519_reduce(fe_f, fe_f);
}

/*
 * Field arithmetic:
 * Use 5*51 bit limbs on 64-bit systems with support for 128 bit arithmetic,
 * and 10*25.5 bit limbs elsewhere.
 *
 * Functions used elsewhere that are candidates for inlining are defined
 * via "private/curve25519_ref10.h".
 */

static inline void
fe25519_sqmul(fe25519 s, const int n, const fe25519 a)
{
    int i;

    for (i = 0; i < n; i++) {
        fe25519_sq(s, s);
    }
    fe25519_mul(s, s, a);
}

static int
fe25519_notsquare(const fe25519 x)
{
    fe25519       _10, _11, _1100, _1111, _11110000, _11111111;
    fe25519       t, u, v;
    unsigned char s[32];

    /* Jacobi symbol - x^((p-1)/2) */
    fe25519_mul(_10, x, x);
    fe25519_mul(_11, x, _10);
    fe25519_sq(_1100, _11);
    fe25519_sq(_1100, _1100);
    fe25519_mul(_1111, _11, _1100);
    fe25519_sq(_11110000, _1111);
    fe25519_sq(_11110000, _11110000);
    fe25519_sq(_11110000, _11110000);
    fe25519_sq(_11110000, _11110000);
    fe25519_mul(_11111111, _1111, _11110000);
    fe25519_copy(t, _11111111);
    fe25519_sqmul(t, 2, _11);
    fe25519_copy(u, t);
    fe25519_sqmul(t, 10, u);
    fe25519_sqmul(t, 10, u);
    fe25519_copy(v, t);
    fe25519_sqmul(t, 30, v);
    fe25519_copy(v, t);
    fe25519_sqmul(t, 60, v);
    fe25519_copy(v, t);
    fe25519_sqmul(t, 120, v);
    fe25519_sqmul(t, 10, u);
    fe25519_sqmul(t, 3, _11);
    fe25519_sq(t, t);

    fe25519_tobytes(s, t);

    return s[1] & 1;
}

static void
fe25519_pow22523(fe25519 out, const fe25519 z)
{
    fe25519 t0;
    fe25519 t1;
    fe25519 t2;
    int     i;

    fe25519_sq(t0, z);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, z, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t0, t0);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 5; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 10; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1);
    for (i = 1; i < 20; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 10; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 50; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1);
    for (i = 1; i < 100; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 50; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t0, t0);
    fe25519_sq(t0, t0);
    fe25519_mul(out, t0, z);
}

static void
fe25519_unchecked_sqrt(fe25519 x, const fe25519 x2)
{
    fe25519 p_root;
    fe25519 m_root;
    fe25519 m_root2;
    fe25519 e;

    fe25519_pow22523(e, x2);
    fe25519_mul(p_root, e, x2);
    fe25519_mul(m_root, p_root, sqrtm1);
    fe25519_sq(m_root2, m_root);
    fe25519_sub(e, x2, m_root2);
    fe25519_copy(x, p_root);
    fe25519_cmov(x, m_root, fe25519_iszero(e));
}

static int
fe25519_sqrt(fe25519 x, const fe25519 x2)
{
    fe25519 check;
    fe25519 x2_copy;

    fe25519_copy(x2_copy, x2);
    fe25519_unchecked_sqrt(x, x2);
    fe25519_sq(check, x);
    fe25519_sub(check, check, x2_copy);

    return fe25519_iszero(check) - 1;
}

/* montgomery -- recover y = sqrt(x^3 + A*x^2 + x) */
static int
ge25519_xmont_to_ymont(fe25519 y, const fe25519 x)
{
    fe25519 x2;
    fe25519 x3;

    fe25519_sq(x2, x);
    fe25519_mul(x3, x, x2);
    fe25519_mul32(x2, x2, ed25519_A_32);
    fe25519_add(y, x3, x);
    fe25519_add(y, y, x2);

    return fe25519_sqrt(y, y);
}

static int
core_h2c_string_to_hash_sha512(unsigned char *h, const size_t h_len, const char *ctx,
                               const unsigned char *msg, size_t msg_len)
{
    crypto_hash_sha512_state st;
    const unsigned char      empty_block[HASH_BLOCKBYTES] = { 0 };
    unsigned char            u0[HASH_BYTES];
    unsigned char            ux[HASH_BYTES] = { 0 };
    unsigned char            t[3] = { 0U, (unsigned char) h_len, 0U};
    unsigned char            ctx_len_u8;
    size_t                   ctx_len = ctx != NULL ? strlen(ctx) : 0U;
    size_t                   i, j;

    assert(h_len <= 0xff);
    if (ctx_len > (size_t) 0xff) {
        crypto_hash_sha512_init(&st);
        crypto_hash_sha512_update(&st,
                                  (const unsigned char *) "H2C-OVERSIZE-DST-",
                                  sizeof "H2C-OVERSIZE-DST-" - 1U);
        crypto_hash_sha512_update(&st, (const unsigned char *) ctx, ctx_len);
        crypto_hash_sha512_final(&st, u0);
        ctx = (const char *) u0;
        ctx_len = HASH_BYTES;
        COMPILER_ASSERT(HASH_BYTES <= (size_t) 0xff);
    }
    ctx_len_u8 = (unsigned char) ctx_len;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, empty_block, sizeof empty_block);
    crypto_hash_sha512_update(&st, msg, msg_len);
    crypto_hash_sha512_update(&st, t, 3U);
    crypto_hash_sha512_update(&st, (const unsigned char *) ctx, ctx_len);
    crypto_hash_sha512_update(&st, &ctx_len_u8, 1U);
    crypto_hash_sha512_final(&st, u0);

    for (i = 0U; i < h_len; i += HASH_BYTES) {
        for (j = 0U; j < HASH_BYTES; j++) {
            ux[j] ^= u0[j];
        }
        t[2]++;
        crypto_hash_sha512_init(&st);
        crypto_hash_sha512_update(&st, ux, HASH_BYTES);
        crypto_hash_sha512_update(&st, &t[2], 1U);
        crypto_hash_sha512_update(&st, (const unsigned char *) ctx, ctx_len);
        crypto_hash_sha512_update(&st, &ctx_len_u8, 1U);
        crypto_hash_sha512_final(&st, ux);
        memcpy(&h[i], ux, h_len - i >= (sizeof ux) ? (sizeof ux) : h_len - i);
    }
    return 0;
}

static void
ge25519_elligator2(fe25519 x, fe25519 y, const fe25519 r, int *notsquare_p)
{
    fe25519       e;
    fe25519       gx1;
    fe25519       rr2;
    fe25519       x2, x3, negx;
    int           notsquare;

    fe25519_sq2(rr2, r);
    rr2[0]++;
    fe25519_invert(rr2, rr2);
    fe25519_mul32(x, rr2, ed25519_A_32);
    fe25519_neg(x, x); /* x=x1 */

    fe25519_sq(x2, x);
    fe25519_mul(x3, x, x2);
    fe25519_mul32(x2, x2, ed25519_A_32); /* x2 = A*x1^2 */
    fe25519_add(gx1, x3, x);
    fe25519_add(gx1, gx1, x2); /* gx1 = x1^3 + A*x1^2 + x1 */

    notsquare = fe25519_notsquare(gx1);

    /* gx1 not a square  => x = -x1-A */
    fe25519_neg(negx, x);
    fe25519_cmov(x, negx, notsquare);
    fe25519_0(x2);
    fe25519_cmov(x2, curve25519_A, notsquare);
    fe25519_sub(x, x, x2);

    /* y = sqrt(gx1) or sqrt(gx2) with gx2 = gx1 * (A+x1) / -x1 */
    /* but it is about as fast to just recompute from the curve equation. */
    if (ge25519_xmont_to_ymont(y, x) != 0) {
        abort();
    }
    *notsquare_p = notsquare;
}

/* montgomery to edwards */
static void
ge25519_mont_to_ed(fe25519 xed, fe25519 yed, const fe25519 x, const fe25519 y)
{
    fe25519 one;
    fe25519 x_plus_one;
    fe25519 x_minus_one;
    fe25519 x_plus_one_y_inv;

    fe25519_1(one);
    fe25519_add(x_plus_one, x, one);
    fe25519_sub(x_minus_one, x, one);

    /* xed = sqrt(-A-2)*x/y */
    fe25519_mul(x_plus_one_y_inv, x_plus_one, y);
    fe25519_invert(x_plus_one_y_inv, x_plus_one_y_inv); /* 1/((x+1)*y) */
    fe25519_mul(xed, x, ed25519_sqrtam2);
    fe25519_mul(xed, xed, x_plus_one_y_inv);            /* sqrt(-A-2)*x/((x+1)*y) */
    fe25519_mul(xed, xed, x_plus_one);

    /* yed = (x-1)/(x+1) */
    fe25519_mul(yed, x_plus_one_y_inv, y);              /* 1/(x+1) */
    fe25519_mul(yed, yed, x_minus_one);
    fe25519_cmov(yed, one, fe25519_iszero(x_plus_one_y_inv));
}

static void
_ext_ge25519_from_hash(unsigned char s[32], const unsigned char h[64])
{
    ge25519_p3    p3;
    fe25519       fe_f;
    fe25519       x, y, negy;
    int           notsquare;
    unsigned char y_sign;

    fe25519_reduce64(fe_f, h);
    ge25519_elligator2(x, y, fe_f, &notsquare);

    y_sign = notsquare ^ 1;
    fe25519_neg(negy, y);
    fe25519_cmov(y, negy, fe25519_isnegative(y) ^ y_sign);

    ge25519_mont_to_ed(p3.X, p3.Y, x, y);

    fe25519_1(p3.Z);
    fe25519_mul(p3.T, p3.X, p3.Y);
    multiply_by_cofactor(&p3);
    ge25519_p3_tobytes(s, &p3);
}

int
_ext_crypto_core_ed25519_from_string(unsigned char p[crypto_core_ed25519_BYTES],
                                const char *ctx, const unsigned char *msg,
                                size_t msg_len)
{
  //return _string_to_points(p, 1, ctx, msg, msg_len, hash_alg);

// _string_to_points(unsigned char * const px, const size_t n,
//                  const char *ctx, const unsigned char *msg, size_t msg_len,
//                  int hash_alg)
    unsigned char h[crypto_core_ed25519_HASHBYTES];
    unsigned char h_be[2U * HASH_GE_L];
    size_t        i, j;

    if (core_h2c_string_to_hash_sha512(h_be, HASH_GE_L, ctx, msg, msg_len) != 0) {
        return -1;
    }
    COMPILER_ASSERT(sizeof h >= HASH_GE_L);
    for (j = 0U; j < HASH_GE_L; j++) {
        h[j] = h_be[i * HASH_GE_L + HASH_GE_L - 1U - j];
    }
    memset(&h[j], 0, (sizeof h) - j);
    _ext_ge25519_from_hash(&p[i * crypto_core_ed25519_BYTES], h);

    return 0;
}
