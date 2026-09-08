#include "poseidon_util.h"
#include "blst_util.h"

#include <assert.h>

/*
 * A binding marshalling blst_fr values into the context buffer must size
 * them with the CARDANO_BLST_FR_SIZE constant, so verify at compile time
 * that it matches the actual blst ABI, following the cbits/blst_util.c
 * pattern.
 */
static_assert(sizeof(blst_fr) == CARDANO_BLST_FR_SIZE, "blst_fr ABI size mismatch");

/*
 * Upper bound on every parameter accepted by poseidon_parameters_valid.
 *
 * This bound keeps the int arithmetic inside
 * poseidon_compute_number_of_constants far away from signed overflow
 * (undefined behavior): with all parameters <= 512 the computed constant
 * count stays below 2^29. It also caps the variable-length arrays in
 * poseidon.c (the largest, in poseidon_apply_batched_partial_round, is
 * state_size + batch_size - 1 <= 1023 blst_fr elements, ~33 KB of stack) --
 * relevant because the permutation runs on whatever thread stack the
 * caller (e.g. a Haskell RTS) provides. Real Poseidon instances use widths
 * below ~24 and round counts in the low hundreds, so the bound does not
 * restrict any legitimate configuration.
 */
#define POSEIDON_MAX_PARAMETER 512

int poseidon_parameters_valid(int nb_full_rounds, int nb_partial_rounds,
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
    return 0;
  if (batch_size > POSEIDON_MAX_PARAMETER || width > POSEIDON_MAX_PARAMETER ||
      nb_full_rounds > POSEIDON_MAX_PARAMETER ||
      nb_partial_rounds > POSEIDON_MAX_PARAMETER)
    return 0;
  return 1;
}

size_t poseidon_ctxt_sizeof(void) { return sizeof(poseidon_ctxt_t); }

void poseidon_ctxt_init(poseidon_ctxt_t *ctxt, blst_fr *buffer,
                        int nb_full_rounds, int nb_partial_rounds,
                        int batch_size, int width) {
  /*
   * The buffer layout ([ state | MDS | constants ]) is not this function's
   * business: it is defined by the poseidon_get_* accessors in poseidon.c
   * (poseidon_get_mds_from_context returns state + width,
   * poseidon_get_round_constants_from_context returns
   * state + width + width * width), and the caller reaches the regions only
   * through those accessors. This function only records the buffer and the
   * parameters in the struct -- the one write that requires knowing the
   * struct's field layout, which is why it lives in C.
   */
  ctxt->state = buffer;
  ctxt->nb_full_rounds = nb_full_rounds;
  ctxt->nb_partial_rounds = nb_partial_rounds;
  ctxt->batch_size = batch_size;
  ctxt->state_size = width;
}
