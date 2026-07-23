#pragma once

#include "poseidon.h"

/*
 * Allocation and validation helpers around the vendored poseidon.c, which
 * itself allocates nothing and validates nothing.
 *
 * The Haskell binding (Cardano.Crypto.Poseidon.Internal) constructs contexts
 * exclusively through poseidon_ctxt_new so that the struct layout of
 * poseidon_ctxt_t never has to be replicated as hand-written byte offsets on
 * the Haskell side (which would silently break on any ABI difference between
 * platforms or compilers). Field access from Haskell likewise goes through
 * the poseidon_get_* accessors declared in poseidon.h.
 */

/*
 * Allocate a poseidon context together with its backing buffer, laid out as
 * poseidon.c expects:
 *
 *   [ state: width | MDS matrix: width * width, row-major | round constants ]
 *
 * The number of round constants is computed internally with
 * poseidon_compute_number_of_constants and already includes `width` trailing
 * zero constants (see poseidon_util.c). The whole buffer is zero-initialized;
 * the caller only writes the state, the MDS and the raw round constants, and
 * must leave the trailing zero constants untouched.
 *
 * Returns NULL if the parameters are invalid (batch_size < 1, width < 2,
 * negative or odd nb_full_rounds, negative nb_partial_rounds, any parameter
 * greater than 512) or if allocation fails. The rationale for each rule is
 * documented at the check in poseidon_util.c.
 */
poseidon_ctxt_t *poseidon_ctxt_new(int nb_full_rounds, int nb_partial_rounds,
                                   int batch_size, int width);

/*
 * Free a context allocated by poseidon_ctxt_new, including its backing
 * buffer. NULL is a no-op. Suitable as a Haskell ForeignPtr finalizer.
 */
void poseidon_ctxt_free(poseidon_ctxt_t *ctxt);
