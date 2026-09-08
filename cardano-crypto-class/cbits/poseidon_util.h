#pragma once

#include "poseidon.h"

/*
 * Validation and initialization helpers around the vendored poseidon.c,
 * which itself allocates nothing and validates nothing.
 *
 * These helpers are written for a foreign-language binding (e.g. Haskell)
 * that allocates all memory itself (for a Haskell binding: RTS-managed
 * pinned memory, so allocation cannot fail with NULL; exhaustion surfaces
 * as an exception). What stays in C is every fact about the C ABI: the
 * size of poseidon_ctxt_t (poseidon_ctxt_sizeof), the writing of its
 * fields (poseidon_ctxt_init) -- so the struct layout never has to be
 * replicated as hand-written byte offsets on the binding side, which would
 * silently break on any ABI difference between platforms or compilers --
 * and the parameter rules that keep poseidon.c away from undefined
 * behavior (poseidon_parameters_valid). Field access from the binding must
 * likewise go through the poseidon_get_* accessors declared in poseidon.h.
 */

/*
 * The number of bytes of a poseidon_ctxt_t, for the caller to allocate. A
 * binding must never hardcode this size: it is an ABI fact that this
 * function exists to own.
 */
size_t poseidon_ctxt_sizeof(void);

/*
 * Returns 1 if the parameters form a configuration poseidon.c can safely
 * run, 0 otherwise. Rejected: batch_size < 1, width < 2, negative or odd
 * nb_full_rounds, negative nb_partial_rounds, any parameter greater than
 * 512. The rationale for each rule is documented at the check in
 * poseidon_util.c. This predicate is the single home of these rules; it
 * must be consulted before poseidon_ctxt_init and before sizing the
 * element buffer (the constant-count arithmetic is only overflow-safe for
 * parameters this predicate accepts).
 *
 * This is a SAFETY predicate, not a strength check: nb_full_rounds = 0 is
 * deliberately accepted (the constant accounting still balances and nothing
 * in poseidon.c misbehaves), even though such an instance is
 * cryptographically meaningless. Judging parameter strength is the job of
 * the layer that defines instances, not of this guard.
 *
 * BEWARE the argument order: this helper and poseidon_ctxt_init take
 * (nb_full_rounds, nb_partial_rounds, batch_size, width), but the vendored
 * poseidon_compute_number_of_constants takes
 * (batch_size, nb_partial_rounds, nb_full_rounds, width). All four
 * parameters are int, so a swapped call compiles silently and yields a
 * wrong-but-plausible result.
 */
int poseidon_parameters_valid(int nb_full_rounds, int nb_partial_rounds,
                              int batch_size, int width);

/*
 * Initialize a caller-allocated poseidon_ctxt_t with a caller-allocated
 * element buffer, laid out as poseidon.c expects:
 *
 *   [ state: width | MDS matrix: width * width, row-major | round constants ]
 *
 * Preconditions (the caller's obligations; nothing is checked here):
 *
 * - the parameters were accepted by poseidon_parameters_valid;
 * - ctxt points to at least poseidon_ctxt_sizeof() bytes;
 * - buffer points to at least
 *     (width + width * width + poseidon_compute_number_of_constants(...))
 *   blst_fr elements, ZERO-INITIALIZED by the caller: the trailing `width`
 *   round constants must be zero (the permutation's final constant addition
 *   consumes them), and zeroed memory provides them without a separate
 *   write;
 * - buffer stays alive for as long as ctxt is used (the struct stores the
 *   pointer; it takes no ownership).
 *
 * After this call the caller writes the MDS and the leading round constants
 * through the poseidon_get_* accessors and must leave the trailing zero
 * constants untouched.
 */
void poseidon_ctxt_init(poseidon_ctxt_t *ctxt, blst_fr *buffer,
                        int nb_full_rounds, int nb_partial_rounds,
                        int batch_size, int width);
