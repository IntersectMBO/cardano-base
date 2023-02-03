#include "crypto_vrf_ietfdraft03.h"
#include "../crypto_vrf.h"

size_t
crypto_vrf_ietfdraft03_bytes(void)
{
    return crypto_vrf_ietfdraft03_BYTES;
}

size_t
crypto_vrf_ietfdraft03_outputbytes(void)
{
    return crypto_vrf_ietfdraft03_OUTPUTBYTES;
}

size_t
crypto_vrf_ietfdraft03_seedbytes(void)
{
    return crypto_vrf_ietfdraft03_SEEDBYTES;
}

size_t
crypto_vrf_ietfdraft03_publickeybytes(void)
{
    return crypto_vrf_ietfdraft03_PUBLICKEYBYTES;
}

size_t
crypto_vrf_ietfdraft03_secretkeybytes(void)
{
    return crypto_vrf_ietfdraft03_SECRETKEYBYTES;
}

/*
 * We keep the functions below to be backwards compatible with older
 * versions of the cardano node, but these are identical as those
 * without the versioning in crypto_vrf.h
 */
int crypto_vrf_ietfdraft03_keypair_from_seed(unsigned char *pk, unsigned char *skpk,
                                             const unsigned char *seed)
{
    return crypto_vrf_seed_keypair(pk, skpk, seed);
}

void crypto_vrf_ietfdraft03_sk_to_pk(unsigned char *pk,
                                     const unsigned char *skpk)
{
    crypto_vrf_sk_to_pk(pk, skpk);
}

void crypto_vrf_ietfdraft03_sk_to_seed(unsigned char *seed,
                                       const unsigned char *skpk)
{
    crypto_vrf_sk_to_seed(seed, skpk);
}
