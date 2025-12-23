#include "blst.h"
#include <memory.h>
#include <assert.h>
#include "blst_util.h"

/*
 * Verify at compile time that the sizes of the blst types match the expected ABI sizes
 * as defined in blst_util.h.
 */
static_assert(sizeof(blst_p1) == CARDANO_BLST_P1_SIZE, "blst_p1 ABI size mismatch");
static_assert(sizeof(blst_p2) == CARDANO_BLST_P2_SIZE, "blst_p2 ABI size mismatch");
static_assert(sizeof(blst_scalar) == CARDANO_BLST_SCALAR_SIZE, "blst_scalar ABI size mismatch");
static_assert(sizeof(blst_fr) == CARDANO_BLST_FR_SIZE, "blst_fr ABI size mismatch");
static_assert(sizeof(blst_fp12) == CARDANO_BLST_FP12_SIZE, "blst_fp12 ABI size mismatch");
static_assert(sizeof(blst_p1_affine) == CARDANO_BLST_AFFINE1_SIZE, "blst_p1_affine ABI size mismatch");
static_assert(sizeof(blst_p2_affine) == CARDANO_BLST_AFFINE2_SIZE, "blst_p2_affine ABI size mismatch");

const int cardano_blst_success() {
  return BLST_SUCCESS;
}
const int cardano_blst_error_bad_encoding() {
  return BLST_BAD_ENCODING;
}
const int cardano_blst_error_point_not_on_curve() {
  return BLST_POINT_NOT_ON_CURVE;
}
const int cardano_blst_error_point_not_in_group() {
  return BLST_POINT_NOT_IN_GROUP;
}
const int cardano_blst_error_aggr_type_mismatch() {
  return BLST_AGGR_TYPE_MISMATCH;
}
const int cardano_blst_error_verify_fail() {
  return BLST_VERIFY_FAIL;
}
const int cardano_blst_error_pk_is_infinity() {
  return BLST_PK_IS_INFINITY;
}
const int cardano_blst_error_bad_scalar() {
  return BLST_BAD_SCALAR;
}
