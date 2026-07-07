#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <ed25519.h>
#include <sodium.h>

static void secure_clear(void *buf, uint32_t const sz)
{
	sodium_memzero(buf, (size_t) sz);
}

static int ensure_sodium(void)
{
	return sodium_init() < 0 ? -1 : 0;
}

#define SECRET_KEY_SEED_SIZE 32
#define UNENCRYPTED_KEY_SIZE 64
#define PUBLIC_KEY_SIZE      32
#define CHAIN_CODE_SIZE      32

#define FULL_KEY_SIZE (UNENCRYPTED_KEY_SIZE + PUBLIC_KEY_SIZE + CHAIN_CODE_SIZE)

typedef struct {
	uint8_t skey[UNENCRYPTED_KEY_SIZE];
	uint8_t pkey[PUBLIC_KEY_SIZE];
	uint8_t cc[CHAIN_CODE_SIZE];
} key_material;

/* Store a plaintext (unencrypted) secret key as an key_material struct.
 * The skey field holds the raw secret bytes; callers unwrap with v2 Argon2id
 * + XChaCha20-Poly1305 at the Haskell layer, not here. */
static void wallet_initialize
    (const ed25519_secret_key secret_key,
     const uint8_t cc[CHAIN_CODE_SIZE],
     key_material *out)
{
	ed25519_public_key pub_key;
	CCW_FN (ed25519_publickey) (secret_key, pub_key);
	memcpy(out->skey, secret_key, UNENCRYPTED_KEY_SIZE);
	memcpy(out->pkey, pub_key, PUBLIC_KEY_SIZE);
	memcpy(out->cc, cc, CHAIN_CODE_SIZE);
}

int CCW_FN (from_secret)
    (const uint8_t seed[SECRET_KEY_SEED_SIZE],
     const uint8_t cc[CHAIN_CODE_SIZE],
     key_material *out)
{
	ed25519_secret_key secret_key;
	if (CCW_FN (ed25519_extend) (seed, secret_key)) {
		secure_clear(secret_key, sizeof(secret_key));
		return 1;
	}
	wallet_initialize(secret_key, cc, out);
	secure_clear(secret_key, sizeof(secret_key));
	return 0;
}

int CCW_FN (new_from_mkg)
    (const uint8_t master_key[96],
     key_material *out)
{
	ed25519_secret_key secret_key;
	memcpy(secret_key, master_key, 64);
	secret_key[0] &= 248;   /* clears the bottom 3 bits */
	secret_key[31] &= 0x1F; /* clears the 3 highest bits */
	secret_key[31] |= 64;   /* set the 2nd highest bit */
	wallet_initialize(secret_key, master_key + 64, out);
	secure_clear(secret_key, sizeof(secret_key));
	return 0;
}

/* Validate that the supplied public key matches the secret key.
 * Returns 0 on success (keys consistent), 1 on mismatch. */
int CCW_FN (validate)
    (const uint8_t skey[UNENCRYPTED_KEY_SIZE],
     const uint8_t pkey[PUBLIC_KEY_SIZE])
{
	ed25519_public_key pub_key;

	CCW_FN (ed25519_publickey) (skey, pub_key);
	if (sodium_memcmp(pub_key, pkey, PUBLIC_KEY_SIZE) != 0) {
    secure_clear(pub_key, sizeof(pub_key));
		return 1;
	}
	secure_clear(pub_key, sizeof(pub_key));
	return 0;
}

int CCW_FN (sign)
    (key_material const *in,
     uint8_t const *data, uint32_t const data_len,
     ed25519_signature signature)
{
	ed25519_public_key pub_key;
	CCW_FN (ed25519_publickey) (in->skey, pub_key);
	CCW_FN (ed25519_sign) (data, data_len, in->cc, CHAIN_CODE_SIZE, in->skey, pub_key, signature);
	secure_clear(pub_key, sizeof(pub_key));
	return 0;
}

typedef enum {
	DERIVATION_V1 = 1,
	DERIVATION_V2 = 2,
} derivation_scheme_mode;

static void multiply8_v1(uint8_t *dst, uint8_t *src, int bytes)
{
	int i;
	uint8_t prev_acc = 0;
	for (i = 0; i < bytes; i++) {
		dst[i] = (src[i] << 3) + (prev_acc & 0x8);
		prev_acc = src[i] >> 5;
	}
}

static void multiply8_v2(uint8_t *dst, uint8_t *src, int bytes)
{
	int i;
	uint8_t prev_acc = 0;
	for (i = 0; i < bytes; i++) {
		dst[i] = (src[i] << 3) + (prev_acc & 0x7);
		prev_acc = src[i] >> 5;
	}
	dst[bytes] = src[bytes-1] >> 5;
}

static void add_256bits_v1(uint8_t *dst, uint8_t *src1, uint8_t *src2)
{
	int i;
	for (i = 0; i < 32; i++) {
		uint8_t a = src1[i];
		uint8_t b = src2[i];
		uint16_t r = a + b;
		dst[i] = r & 0xff;
	}
}

static void add_256bits_v2(uint8_t *dst, uint8_t *src1, uint8_t *src2)
{
	int i; uint8_t carry = 0;
	for (i = 0; i < 32; i++) {
		uint8_t a = src1[i];
		uint8_t b = src2[i];
		uint16_t r = (uint16_t) a + (uint16_t) b + (uint16_t) carry;
		dst[i] = r & 0xff;
		carry = (r >= 0x100) ? 1 : 0;
	}
}

#define TAG_DERIVE_Z_NORMAL    "\x2"
#define TAG_DERIVE_Z_HARDENED  "\x0"
#define TAG_DERIVE_CC_NORMAL   "\x3"
#define TAG_DERIVE_CC_HARDENED "\x1"

static int index_is_hardened(uint32_t index)
{
	return (index & (1 << 31));
}

static void scalar_add_no_overflow(const ed25519_secret_key sk1, const ed25519_secret_key sk2, ed25519_secret_key res)
{
    uint16_t r = 0; int i;
    for (i = 0; i < 32; i++) {
	    r = (uint16_t) sk1[i] + (uint16_t) sk2[i] + r;
	    res[i] = (uint8_t) r;
	    r >>= 8;
    }
}

static void serialize_index32(uint8_t *out, uint32_t index, derivation_scheme_mode mode)
{
	switch (mode) {
	case DERIVATION_V1: /* BIG ENDIAN */
		out[0] = index >> 24;
		out[1] = index >> 16;
		out[2] = index >> 8;
		out[3] = index;
		break;
	case DERIVATION_V2: /* LITTLE ENDIAN */
		out[3] = index >> 24;
		out[2] = index >> 16;
		out[1] = index >> 8;
		out[0] = index;
		break;
	}
}

static void add_left(ed25519_secret_key res_key, uint8_t *z, ed25519_secret_key priv_key, derivation_scheme_mode mode)
{
	ed25519_secret_key zl8;

	memset(zl8, 0, 64);
	switch (mode) {
	case DERIVATION_V1:
		multiply8_v1(zl8, z, 32);
		CCW_FN (ed25519_scalar_add) (zl8, priv_key, res_key);
		break;
	case DERIVATION_V2:
		multiply8_v2(zl8, z, 28);
		scalar_add_no_overflow(zl8, priv_key, res_key);
		break;
	}
	secure_clear(zl8, 64);
}

static void add_right(ed25519_secret_key res_key, uint8_t *z, ed25519_secret_key priv_key, derivation_scheme_mode mode)
{
	switch (mode) {
	case DERIVATION_V1:
		add_256bits_v1(res_key + 32, z+32, priv_key+32);
		break;
	case DERIVATION_V2:
		add_256bits_v2(res_key + 32, z+32, priv_key+32);
		break;
	}
}

static void add_left_public(uint8_t *out, uint8_t *z, uint8_t *in, derivation_scheme_mode mode)
{
	ed25519_secret_key zl8;
	ed25519_public_key pub_zl8;

	memset(zl8, 0, 64);
	switch (mode) {
	case DERIVATION_V1:
		multiply8_v1(zl8, z, 32);
		break;
	case DERIVATION_V2:
		multiply8_v2(zl8, z, 28);
		break;
	}

	CCW_FN (ed25519_publickey) (zl8, pub_zl8);
	CCW_FN (ed25519_point_add) (pub_zl8, in, out);
	secure_clear(zl8, 64);
}

int CCW_FN (derive_private)
    (key_material const *in,
     uint32_t index,
     key_material *out,
     derivation_scheme_mode mode)
{
	ed25519_secret_key priv_key;
	ed25519_secret_key res_key;
	crypto_auth_hmacsha512_state hmac_ctx;
	uint8_t idxBuf[4];
	uint8_t z[64];
	uint8_t hmac_out[64];

	memcpy(priv_key, in->skey, UNENCRYPTED_KEY_SIZE);

	serialize_index32(idxBuf, index, mode);

	/* calculate Z */
	crypto_auth_hmacsha512_init(&hmac_ctx, in->cc, CHAIN_CODE_SIZE);
	if (index_is_hardened(index)) {
		crypto_auth_hmacsha512_update(&hmac_ctx, TAG_DERIVE_Z_HARDENED, 1);
		crypto_auth_hmacsha512_update(&hmac_ctx, in->skey, UNENCRYPTED_KEY_SIZE);
	} else {
		crypto_auth_hmacsha512_update(&hmac_ctx, TAG_DERIVE_Z_NORMAL, 1);
		crypto_auth_hmacsha512_update(&hmac_ctx, in->pkey, PUBLIC_KEY_SIZE);
	}
	crypto_auth_hmacsha512_update(&hmac_ctx, idxBuf, 4);
	crypto_auth_hmacsha512_final(&hmac_ctx, z);

	add_left(res_key, z, priv_key, mode);
	add_right(res_key, z, priv_key, mode);

	/* calculate the new chain code */
	crypto_auth_hmacsha512_init(&hmac_ctx, in->cc, CHAIN_CODE_SIZE);
	if (index_is_hardened(index)) {
		crypto_auth_hmacsha512_update(&hmac_ctx, TAG_DERIVE_CC_HARDENED, 1);
		crypto_auth_hmacsha512_update(&hmac_ctx, in->skey, UNENCRYPTED_KEY_SIZE);
	} else {
		crypto_auth_hmacsha512_update(&hmac_ctx, TAG_DERIVE_CC_NORMAL, 1);
		crypto_auth_hmacsha512_update(&hmac_ctx, in->pkey, PUBLIC_KEY_SIZE);
	}
	crypto_auth_hmacsha512_update(&hmac_ctx, idxBuf, 4);
	crypto_auth_hmacsha512_final(&hmac_ctx, hmac_out);

	wallet_initialize(res_key, hmac_out + 32, out);

	secure_clear(priv_key, UNENCRYPTED_KEY_SIZE);
	secure_clear(res_key, UNENCRYPTED_KEY_SIZE);
	secure_clear(hmac_out, 64);
	secure_clear(z, 64);
	secure_clear(idxBuf, sizeof(idxBuf));
	secure_clear(&hmac_ctx, sizeof(hmac_ctx));
	return 0;
}

int CCW_FN (derive_public)
    (uint8_t *pub_in,
     uint8_t *cc_in,
     uint32_t index,
     uint8_t *pub_out,
     uint8_t *cc_out,
     derivation_scheme_mode mode)
{
	crypto_auth_hmacsha512_state hmac_ctx;
	uint8_t idxBuf[4];
	uint8_t z[64];
	uint8_t hmac_out[64];

	if (index_is_hardened(index))
		return 1;

	serialize_index32(idxBuf, index, mode);

	crypto_auth_hmacsha512_init(&hmac_ctx, cc_in, CHAIN_CODE_SIZE);
	crypto_auth_hmacsha512_update(&hmac_ctx, TAG_DERIVE_Z_NORMAL, 1);
	crypto_auth_hmacsha512_update(&hmac_ctx, pub_in, PUBLIC_KEY_SIZE);
	crypto_auth_hmacsha512_update(&hmac_ctx, idxBuf, 4);
	crypto_auth_hmacsha512_final(&hmac_ctx, z);

	add_left_public(pub_out, z, pub_in, mode);

	crypto_auth_hmacsha512_init(&hmac_ctx, cc_in, CHAIN_CODE_SIZE);
	crypto_auth_hmacsha512_update(&hmac_ctx, TAG_DERIVE_CC_NORMAL, 1);
	crypto_auth_hmacsha512_update(&hmac_ctx, pub_in, PUBLIC_KEY_SIZE);
	crypto_auth_hmacsha512_update(&hmac_ctx, idxBuf, 4);
	crypto_auth_hmacsha512_final(&hmac_ctx, hmac_out);

	memcpy(cc_out, hmac_out + (sizeof(hmac_out) - CHAIN_CODE_SIZE), CHAIN_CODE_SIZE);
	secure_clear(z, 64);
	secure_clear(hmac_out, 64);
	secure_clear(idxBuf, sizeof(idxBuf));
	secure_clear(&hmac_ctx, sizeof(hmac_ctx));

	return 0;
}

int CCW_FN (randombytes) (void * const out, size_t const out_len)
{
	if (ensure_sodium() != 0) {
		return 1;
	}
	randombytes_buf(out, out_len);
	return 0;
}

int CCW_FN (argon2id) (uint8_t *out,
	uint8_t const *pass,
	unsigned long long pass_len,
	uint8_t const salt[crypto_pwhash_SALTBYTES],
	unsigned long long opslimit,
	size_t memlimit)
{
	if (ensure_sodium() != 0) {
		return 1;
	}
	return crypto_pwhash(out,
		crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
		(const char *) pass,
		pass_len,
		salt,
		opslimit,
		memlimit,
		crypto_pwhash_ALG_ARGON2ID13);
}

int CCW_FN (xchacha20poly1305_encrypt) (
	uint8_t *ciphertext,
	uint8_t tag[crypto_aead_xchacha20poly1305_ietf_ABYTES],
	uint8_t const secret_to_encrypt[UNENCRYPTED_KEY_SIZE],
	uint8_t const *aad,
	unsigned long long aad_len,
	uint8_t const nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
	uint8_t const key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
{
	unsigned long long clen = 0;
	uint8_t combined[crypto_aead_xchacha20poly1305_ietf_ABYTES + UNENCRYPTED_KEY_SIZE];

	if (ensure_sodium() != 0) {
		return 1;
	}
	if (crypto_aead_xchacha20poly1305_ietf_encrypt(
		combined,
		&clen,
		secret_to_encrypt,
		UNENCRYPTED_KEY_SIZE,
		aad,
		aad_len,
		NULL,
		nonce,
		key) != 0) {
		secure_clear(combined, sizeof(combined));
		return 1;
	}
	memcpy(ciphertext, combined, (size_t) UNENCRYPTED_KEY_SIZE);
	memcpy(tag, combined + UNENCRYPTED_KEY_SIZE, clen - UNENCRYPTED_KEY_SIZE);
	secure_clear(combined, sizeof(combined));
	return 0;
}

int CCW_FN (xchacha20poly1305_decrypt) (
	uint8_t *secret_to_decrypt,
	uint8_t const *ciphertext,
	uint8_t const tag[crypto_aead_xchacha20poly1305_ietf_ABYTES],
	uint8_t const *aad,
	unsigned long long aad_len,
	uint8_t const nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],
	uint8_t const key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
{
	unsigned long long plen = 0;
	uint8_t combined[crypto_aead_xchacha20poly1305_ietf_ABYTES + UNENCRYPTED_KEY_SIZE];

	if (ensure_sodium() != 0) {
		return 1;
	}
	memcpy(combined, ciphertext, (size_t) UNENCRYPTED_KEY_SIZE);
	memcpy(combined + UNENCRYPTED_KEY_SIZE, tag, crypto_aead_xchacha20poly1305_ietf_ABYTES);
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(
		secret_to_decrypt,
		&plen,
		NULL,
		combined,
		UNENCRYPTED_KEY_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES,
		aad,
		aad_len,
		nonce,
		key) != 0) {
		secure_clear(combined, sizeof(combined));
		return 1;
	}
	secure_clear(combined, sizeof(combined));
	return (plen == UNENCRYPTED_KEY_SIZE) ? 0 : 1;
}
