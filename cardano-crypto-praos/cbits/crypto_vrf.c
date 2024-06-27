#include "sodium/crypto_hash_sha512.h"
#include "private/ed25519_ref10.h"
#include "sodium/randombytes.h"
#include "crypto_vrf.h"

size_t
cardano_crypto_vrf_publickeybytes(void)
{
    return cardano_crypto_vrf_PUBLICKEYBYTES;
}

size_t
cardano_crypto_vrf_secretkeybytes(void)
{
    return cardano_crypto_vrf_SECRETKEYBYTES;
}

size_t
cardano_crypto_vrf_seedbytes(void)
{
    return cardano_crypto_vrf_SEEDBYTES;
}

size_t
cardano_crypto_vrf_proofbytes(void)
{
    return crypto_vrf_PROOFBYTES;
}

size_t
cardano_crypto_vrf_outputbytes(void)
{
    return cardano_crypto_vrf_OUTPUTBYTES;
}

const char *
cardano_crypto_vrf_primitive(void)
{
    return cardano_crypto_vrf_PRIMITIVE;
}

int
crypto_vrf_seed_keypair(unsigned char *pk, unsigned char *skpk,
                        const unsigned char *seed)
{
    ge25519_p3 A;

    crypto_hash_sha512(skpk, seed, 32);
    skpk[0] &= 248;
    skpk[31] &= 127;
    skpk[31] |= 64;

    cardano_ge25519_scalarmult_base(&A, skpk);
    cardano_ge25519_p3_tobytes(pk, &A);

    memmove(skpk, seed, 32);
    memmove(skpk + 32, pk, 32);

    return 0;
}

int
cardano_crypto_vrf_keypair(unsigned char *pk, unsigned char *skpk)
{
    unsigned char seed[32];
    int           ret;

    randombytes_buf(seed, sizeof seed);
    ret = crypto_vrf_seed_keypair(pk, skpk, seed);
    sodium_memzero(seed, sizeof seed);

    return ret;
}

int
cardano_crypto_vrf_prove(unsigned char *proof, const unsigned char *skpk,
		 const unsigned char *m, const unsigned long long mlen)
{
    return crypto_vrf_ietfdraft13_prove(proof, skpk, m, mlen);
}

int
cardano_crypto_vrf_verify(unsigned char *output, const unsigned char *pk,
		  const unsigned char *proof, const unsigned char *m,
		  const unsigned long long mlen)
{
    return crypto_vrf_ietfdraft13_verify(output, pk, proof, m, mlen);
}

int
cardano_crypto_vrf_proof_to_hash(unsigned char *hash, const unsigned char *proof)
{
    return crypto_vrf_ietfdraft13_proof_to_hash(hash, proof);
}

void
crypto_vrf_sk_to_pk(unsigned char *pk, const unsigned char *skpk)
{
    memmove(pk, skpk+32, 32);
}

void
crypto_vrf_sk_to_seed(unsigned char *seed, const unsigned char *skpk)
{
    memmove(seed, skpk, 32);
}
