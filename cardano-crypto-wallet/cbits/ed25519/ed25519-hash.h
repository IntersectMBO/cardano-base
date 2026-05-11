#include <sodium.h>
typedef crypto_hash_sha512_state ed25519_hash_context;

static void
ed25519_hash_init(ed25519_hash_context *ctx) {
	crypto_hash_sha512_init(ctx);
}

static void
ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
	crypto_hash_sha512_update(ctx, in, inlen);
}

static void
ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
	crypto_hash_sha512_final(ctx, hash);
}

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	ed25519_hash_context ctx;
	crypto_hash_sha512_init(&ctx);
	crypto_hash_sha512_update(&ctx, in, inlen);
	crypto_hash_sha512_final(&ctx, hash);
	sodium_memzero(&ctx, sizeof(ctx));
}
