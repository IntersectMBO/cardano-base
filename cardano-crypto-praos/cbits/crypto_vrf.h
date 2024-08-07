#ifndef crypto_vrf_H
#define crypto_vrf_H

/*
 * THREAD SAFETY: cardano_crypto_vrf_keypair() is thread-safe provided that
 * sodium_init() was called before.
 *
 * Other functions, including cardano_crypto_vrf_keypair_from_seed(), are always
 * thread-safe.
 */

#include <stddef.h>

#include "vrf13_batchcompat/crypto_vrf_ietfdraft13.h"
#include "sodium/export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

static const unsigned char SUITE = 0x04; /* ECVRF-ED25519-SHA512-ELL2 */

static const unsigned char ZERO = 0x00;
static const unsigned char ONE = 0x01;
static const unsigned char TWO = 0x02;
static const unsigned char THREE = 0x03;

#define cardano_crypto_vrf_PUBLICKEYBYTES crypto_vrf_ietfdraft13_PUBLICKEYBYTES
SODIUM_EXPORT
size_t cardano_crypto_vrf_publickeybytes(void);

#define cardano_crypto_vrf_SECRETKEYBYTES crypto_vrf_ietfdraft13_SECRETKEYBYTES
SODIUM_EXPORT
size_t cardano_crypto_vrf_secretkeybytes(void);

#define cardano_crypto_vrf_SEEDBYTES crypto_vrf_ietfdraft13_SEEDBYTES
SODIUM_EXPORT
size_t cardano_crypto_vrf_seedbytes(void);

#define crypto_vrf_PROOFBYTES crypto_vrf_ietfdraft13_BYTES
SODIUM_EXPORT
size_t cardano_crypto_vrf_proofbytes(void);

#define cardano_crypto_vrf_OUTPUTBYTES crypto_vrf_ietfdraft13_OUTPUTBYTES
SODIUM_EXPORT
size_t cardano_crypto_vrf_outputbytes(void);

#define cardano_crypto_vrf_PRIMITIVE "ietfdraft13"
SODIUM_EXPORT
const char *cardano_crypto_vrf_primitive(void);

SODIUM_EXPORT
int cardano_crypto_vrf_keypair(unsigned char *pk, unsigned char *skpk)
__attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_vrf_seed_keypair(unsigned char *pk, unsigned char *skpk,
				 const unsigned char *seed)
__attribute__ ((nonnull));

SODIUM_EXPORT
int cardano_crypto_vrf_prove(unsigned char *proof, const unsigned char *skpk,
		     const unsigned char *m, unsigned long long mlen)
__attribute__ ((nonnull));

SODIUM_EXPORT
int cardano_crypto_vrf_verify(unsigned char *output,
		      const unsigned char *pk,
		      const unsigned char *proof,
		      const unsigned char *m, unsigned long long mlen)
            __attribute__ ((warn_unused_result))
__attribute__ ((warn_unused_result))  __attribute__ ((nonnull));

SODIUM_EXPORT
int cardano_crypto_vrf_proof_to_hash(unsigned char *hash, const unsigned char *proof);

SODIUM_EXPORT
void crypto_vrf_sk_to_pk(unsigned char *pk, const unsigned char *skpk);

SODIUM_EXPORT
void crypto_vrf_sk_to_seed(unsigned char *seed, const unsigned char *skpk);

#ifdef __cplusplus
}
#endif

#endif
