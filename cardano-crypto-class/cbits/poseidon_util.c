#include "poseidon_util.h"
#include "blst_util.h"

#include <assert.h>
#include <stdlib.h>

/*
 * The Haskell binding marshals blst_fr values into the context buffer using
 * the CARDANO_BLST_FR_SIZE constant (via sizeFr), so verify at compile time
 * that it matches the actual blst ABI, following the cbits/blst_util.c
 * pattern.
 */
static_assert(sizeof(blst_fr) == CARDANO_BLST_FR_SIZE, "blst_fr ABI size mismatch");

/*
 * Upper bound on every parameter accepted by poseidon_ctxt_new.
 *
 * This bound keeps the int arithmetic inside
 * poseidon_compute_number_of_constants far away from signed overflow
 * (undefined behavior): with all parameters <= 512 the computed constant
 * count stays below 2^29. Real Poseidon instances use widths below ~24 and
 * round counts in the low hundreds, so the bound does not restrict any
 * legitimate configuration.
 */
#define POSEIDON_MAX_PARAMETER 512

poseidon_ctxt_t *poseidon_ctxt_new(int nb_full_rounds, int nb_partial_rounds,
                                   int batch_size, int width) {
  /*
   * poseidon.c validates nothing, so every precondition must be rejected
   * here:
   *
   * - batch_size < 1: poseidon_apply_permutation divides the partial round
   *   count by batch_size (division by zero for 0), and
   *   poseidon_apply_batched_partial_round declares a variable-length array
   *   whose length involves batch_size - 1 (negative length for 0) -- both
   *   undefined behavior.
   *
   * - nb_full_rounds odd: the permutation executes nb_full_rounds / 2 full
   *   rounds before and after the partial rounds (integer division), i.e.
   *   one round fewer than poseidon_compute_number_of_constants budgets
   *   constants for. The result would be a silently wrong digest, not a
   *   crash, so it must be caught here.
   *
   * - nb_full_rounds or nb_partial_rounds negative: the round loops would
   *   not execute, but the constant accounting would be inconsistent with
   *   what the permutation consumes; no meaningful instance has negative
   *   round counts.
   *
   * - width < 2: the sponge construction needs at least one capacity and
   *   one rate element, and width <= 0 would make the state and MDS VLAs in
   *   poseidon.c undefined behavior.
   */
  if (batch_size < 1 || width < 2 || nb_full_rounds < 0 ||
      (nb_full_rounds % 2) != 0 || nb_partial_rounds < 0)
    return NULL;
  if (batch_size > POSEIDON_MAX_PARAMETER || width > POSEIDON_MAX_PARAMETER ||
      nb_full_rounds > POSEIDON_MAX_PARAMETER ||
      nb_partial_rounds > POSEIDON_MAX_PARAMETER)
    return NULL;

  int nb_constants = poseidon_compute_number_of_constants(
      batch_size, nb_partial_rounds, nb_full_rounds, width);

  /*
   * Single contiguous buffer in the layout the poseidon.c accessors assume:
   *
   *   [ state: width | MDS: width * width, row-major | constants: nb_constants ]
   *
   * poseidon_get_mds_from_context returns state + width and
   * poseidon_get_round_constants_from_context returns
   * state + width + width * width; getting this order wrong produces
   * silently wrong digests, so it is encoded exactly once, here.
   *
   * calloc (rather than malloc) is load-bearing: the permutation's final
   * constant addition consumes `width` constants that the algorithm requires
   * to be zero (the last round has no ARK addition; the implementation pads
   * with zeros instead of branching). poseidon_compute_number_of_constants
   * already counts these `width` trailing zeros, and zero-initialized memory
   * provides them without relying on the caller to write them.
   */
  size_t nb_elements =
      (size_t)width + (size_t)width * (size_t)width + (size_t)nb_constants;
  blst_fr *buffer = calloc(nb_elements, sizeof(blst_fr));
  if (buffer == NULL)
    return NULL;

  poseidon_ctxt_t *ctxt = malloc(sizeof(poseidon_ctxt_t));
  if (ctxt == NULL) {
    free(buffer);
    return NULL;
  }
  ctxt->state = buffer;
  ctxt->nb_full_rounds = nb_full_rounds;
  ctxt->nb_partial_rounds = nb_partial_rounds;
  ctxt->batch_size = batch_size;
  ctxt->state_size = width;
  return ctxt;
}

void poseidon_ctxt_free(poseidon_ctxt_t *ctxt) {
  if (ctxt != NULL) {
    free(ctxt->state);
    free(ctxt);
  }
}
