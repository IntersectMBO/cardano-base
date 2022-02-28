#include <blst.h>
#include <memory.h>

const size_t size_blst_p1 () { return sizeof(blst_p1); }
const size_t size_blst_p2 () { return sizeof(blst_p2); }
const size_t size_blst_scalar () { return sizeof(blst_scalar); }
const size_t size_blst_fr () { return sizeof(blst_fr); }
const size_t size_blst_affine1 () { return sizeof(blst_p1_affine); }
const size_t size_blst_affine2 () { return sizeof(blst_p2_affine); }

const int blst_success () { return BLST_SUCCESS; }
const int blst_error_bad_encoding () { return BLST_BAD_ENCODING; }
const int blst_error_point_not_on_curve () { return BLST_POINT_NOT_ON_CURVE; }
const int blst_error_point_not_in_group () { return BLST_POINT_NOT_IN_GROUP; }
const int blst_error_aggr_type_mismatch () { return BLST_AGGR_TYPE_MISMATCH; }
const int blst_error_verify_fail () { return BLST_VERIFY_FAIL; }
const int blst_error_pk_is_infinity () { return BLST_PK_IS_INFINITY; }
const int blst_error_bad_scalar () { return BLST_BAD_SCALAR; }

bool blst_two_miller_one_exp(const blst_p1_affine *a1, const blst_p1_affine *a2, const blst_p2_affine *a3, const blst_p2_affine *a4)
{
        blst_fp12 lhs;
        blst_miller_loop(&lhs, a3, a1);

        blst_fp12 rhs;
        blst_miller_loop(&rhs, a4, a2);

        blst_fp12 res_fin_exp;
        blst_fp12_mul(&res_fin_exp, &lhs, &rhs);

        blst_fp12 final_exp;
        blst_final_exp(&final_exp, &res_fin_exp);

        return blst_fp12_is_one(&final_exp);
}

void blst_x_from_p1(blst_fp *dst, const blst_p1 *p) { memcpy(dst, &p->x, sizeof(blst_fp)); }
void blst_y_from_p1(blst_fp *dst, const blst_p1 *p) { memcpy(dst, &p->y, sizeof(blst_fp)); }
void blst_z_from_p1(blst_fp *dst, const blst_p1 *p) { memcpy(dst, &p->z, sizeof(blst_fp)); }
void blst_x_from_p2(blst_fp *dst, const blst_p2 *p) { memcpy(dst, &p->x, sizeof(blst_fp)); }
void blst_y_from_p2(blst_fp *dst, const blst_p2 *p) { memcpy(dst, &p->y, sizeof(blst_fp)); }
void blst_z_from_p2(blst_fp *dst, const blst_p2 *p) { memcpy(dst, &p->z, sizeof(blst_fp)); }

void blst_x_from_affine1(blst_fp *dst, const blst_p1_affine *affine) { memcpy(dst, &affine->x, sizeof(blst_fp)); }
void blst_y_from_affine1(blst_fp *dst, const blst_p1_affine *affine) { memcpy(dst, &affine->y, sizeof(blst_fp)); }
void blst_x_from_affine2(blst_fp *dst, const blst_p2_affine *affine) { memcpy(dst, &affine->x, sizeof(blst_fp)); }
void blst_y_from_affine2(blst_fp *dst, const blst_p2_affine *affine) { memcpy(dst, &affine->y, sizeof(blst_fp)); }
