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
    ge25519_from_hash(&p[i * crypto_core_ed25519_BYTES], h);

    return 0;
}
