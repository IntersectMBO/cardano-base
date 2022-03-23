#include "quirks.h"
#include "sodium/crypto_core_ed25519.h"

int
_ext_crypto_core_ed25519_from_string(unsigned char p[crypto_core_ed25519_BYTES],
                                const char *ctx, const unsigned char *msg,
                                size_t msg_len);
