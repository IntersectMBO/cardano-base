#ifndef crypto_vrf_ietfdraft13_H
#define crypto_vrf_ietfdraft13_H

#include <stddef.h>

#include "sodium/export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_vrf_ietfdraft13_BYTES 80U
SODIUM_EXPORT
        size_t crypto_vrf_ietfdraft13_bytes(void);

#define crypto_vrf_batchcompat_ietfdraft13_BYTES 128U
SODIUM_EXPORT
        size_t crypto_vrf_batchcompat_ietfdraft13_bytes(void);

#define crypto_vrf_ietfdraft13_OUTPUTBYTES 64U
SODIUM_EXPORT
        size_t crypto_vrf_ietfdraft13_outputbytes(void);

#define crypto_vrf_ietfdraft13_SEEDBYTES 32U
SODIUM_EXPORT
        size_t crypto_vrf_ietfdraft13_seedbytes(void);

#define crypto_vrf_ietfdraft13_PUBLICKEYBYTES 32U
SODIUM_EXPORT
        size_t crypto_vrf_ietfdraft13_publickeybytes(void);

#define crypto_vrf_ietfdraft13_SECRETKEYBYTES 64U
SODIUM_EXPORT
        size_t crypto_vrf_ietfdraft13_secretkeybytes(void);

SODIUM_EXPORT
int crypto_vrf_ietfdraft13_prove(unsigned char *proof,
                                 const unsigned char *skpk,
                                 const unsigned char *m,
                                 unsigned long long mlen);

SODIUM_EXPORT
int crypto_vrf_ietfdraft13_prove_batchcompat(unsigned char *proof,
                                             const unsigned char *skpk,
                                             const unsigned char *m,
                                             unsigned long long mlen);

SODIUM_EXPORT
int crypto_vrf_ietfdraft13_verify(unsigned char *output,
                                  const unsigned char *pk,
                                  const unsigned char *proof,
                                  const unsigned char *m,
                                  unsigned long long mlen)
__attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_vrf_ietfdraft13_verify_batchcompat(unsigned char *output,
                                              const unsigned char *pk,
                                              const unsigned char *proof,
                                              const unsigned char *m,
                                              unsigned long long mlen)
__attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_vrf_ietfdraft13_batch_verify(unsigned char *output[64],
                                        const unsigned char *pk[32],
                                        const unsigned char *proof[128],
                                        const unsigned char **msg,
                                        const unsigned long long *msglen,
                                        size_t num)
__attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_vrf_ietfdraft13_proof_to_hash(unsigned char *hash,
                                         const unsigned char *proof)
__attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_vrf_ietfdraft13_proof_to_hash_batchcompat(unsigned char *hash,
                                                     const unsigned char *proof)
__attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
