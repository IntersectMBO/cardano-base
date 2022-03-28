
#include <string.h>

#include "sodium/crypto_hash_sha512.h"
#include "crypto_vrf_ietfdraft10.h"
#include "sodium/crypto_core_ed25519.h"
#include "../private/ed25519_ref10.h"
#include "sodium/randombytes.h"
#include "sodium/utils.h"

int
crypto_vrf_ietfdraft10_keypair(unsigned char pk[crypto_vrf_ietfdraft10_PUBLICKEYBYTES],
                               unsigned char sk[crypto_vrf_ietfdraft10_SECRETKEYBYTES])
{
    unsigned char seed[crypto_vrf_ietfdraft10_SEEDBYTES];

    randombytes_buf(seed, sizeof seed);
    crypto_vrf_ietfdraft10_keypair_from_seed(pk, sk, seed);
    sodium_memzero(seed, sizeof seed);

    return 0;
}

int
crypto_vrf_ietfdraft10_keypair_from_seed(unsigned char pk[crypto_vrf_ietfdraft10_PUBLICKEYBYTES],
                                         unsigned char sk[crypto_vrf_ietfdraft10_SECRETKEYBYTES],
                                         const unsigned char seed[crypto_vrf_ietfdraft10_SEEDBYTES])
{
    ge25519_p3 A;

    crypto_hash_sha512(sk, seed, crypto_vrf_ietfdraft10_SEEDBYTES);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    ge25519_scalarmult_base(&A, sk);
    ge25519_p3_tobytes(pk, &A);
    memmove(sk, seed, crypto_vrf_ietfdraft10_SEEDBYTES);
    memmove(sk + crypto_vrf_ietfdraft10_SEEDBYTES, pk, crypto_vrf_ietfdraft10_PUBLICKEYBYTES);

    return 0;
}

void
crypto_vrf_ietfdraft10_sk_to_pk(unsigned char pk[crypto_vrf_ietfdraft10_PUBLICKEYBYTES],
                                const unsigned char skpk[crypto_vrf_ietfdraft10_SECRETKEYBYTES])
{
    memmove(pk, skpk+crypto_vrf_ietfdraft10_SEEDBYTES, crypto_vrf_ietfdraft10_PUBLICKEYBYTES);
}

void
crypto_vrf_ietfdraft10_sk_to_seed(unsigned char seed[crypto_vrf_ietfdraft10_SEEDBYTES],
                                  const unsigned char skpk[crypto_vrf_ietfdraft10_SECRETKEYBYTES])
{
    memmove(seed, skpk, crypto_vrf_ietfdraft10_SEEDBYTES);
}
