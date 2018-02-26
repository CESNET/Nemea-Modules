//
// Created by slabimic on 24/02/18.
//

#include "agg_functions.h"

/* ================================================================= */
/* ======================= Sum definitions ========================= */
/* ================================================================= */
void sum_int64(const void *src, void *dst)
{
   *((int64_t*)dst) += *((int64_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_int32(const void *src, void *dst)
{
   *((int32_t*)dst) += *((int32_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_int16(const void *src, void *dst)
{
   *((int16_t*)dst) += *((int16_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_int8(const void *src, void *dst)
{
   *((int8_t*)dst) += *((int8_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_uint64(const void *src, void *dst)
{
   *((uint64_t*)dst) += *((uint64_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_uint32(const void *src, void *dst)
{
   *((uint32_t*)dst) += *((uint32_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_uint16(const void *src, void *dst)
{
   *((uint16_t*)dst) += *((uint16_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_uint8(const void *src, void *dst)
{
   *((uint8_t*)dst) += *((uint8_t*)src);
}
/* ----------------------------------------------------------------- */
void sum_float(const void *src, void *dst)
{
   *((float*)dst) += *((float*)src);
}
/* ----------------------------------------------------------------- */
void sum_double(const void *src, void *dst)
{
   *((double*)dst) += *((double*)src);
}
/* ----------------------------------------------------------------- */
/* ================================================================= */
/* ======================= Avg definitions ========================= */
/* ================================================================= */
void avg_int64(const void *src, void *dst)
{
   sum_int64(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_int32(const void *src, void *dst)
{
   sum_int32(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_int16(const void *src, void *dst)
{
   sum_int16(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_int8(const void *src, void *dst)
{
   sum_int8(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_uint64(const void *src, void *dst)
{
   sum_uint64(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_uint32(const void *src, void *dst)
{
   sum_uint32(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_uint16(const void *src, void *dst)
{
   sum_uint16(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_uint8(const void *src, void *dst)
{
   sum_uint8(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_float(const void *src, void *dst)
{
   sum_float(src, dst);
}
/* ----------------------------------------------------------------- */
void avg_double(const void *src, void *dst)
{
   sum_double(src, dst);
}