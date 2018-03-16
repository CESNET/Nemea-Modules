/*! \file agg_functions.h
 */
//
// Created by slabimic on 24/02/18.
//

#include <unirec/unirec.h>

#ifndef AGGREGATOR_AGG_FUNCTIONS_H
#define AGGREGATOR_AGG_FUNCTIONS_H

/**
 *
 * @tparam T
 * @param src
 * @param dst
 */
template <typename T>
void sum(const void *src, void *dst)
{
   *((T*)dst) += *((T*)src);
}

/**
 *
 * @tparam T
 * @param src
 * @param dst
 */
template <typename T>
void avg(const void *src, void *dst)
{
   sum<T>(src, dst);
}

/*
 * Implementation in header file because of errors
 * aggregation_module-configuration.o: undefined reference to `void make_avg<unsigned char>(void*, unsigned int)'
 * ...
*/
/**
 *
 * @tparam T
 * @param src
 * @param count
 */
template <typename T>
void make_avg(void *src, uint32_t count)
{
   *((T*)src) /= count;
}

/**
 *
 * @tparam T
 * @param src
 * @param dst
 */
template <typename T>
void min(const void *src, void *dst)
{
   if (*((T*)src) < *((T*)dst))
      *((T*)dst) = *((T*)src);

}

/**
 *
 * @param src
 * @param dst
 */
void min_ip(const void *src, void *dst);

/**
 *
 * @tparam T
 * @param src
 * @param dst
 */
template <typename T>
void max(const void *src, void *dst)
{
   if (*((T*)src) > *((T*)dst))
      *((T*)dst) = *((T*)src);

}

/**
 *
 * @param src
 * @param dst
 */
void max_ip(const void *src, void *dst);

/**
 *
 * @param src
 * @param dst
 */
void nope(const void *src, void *dst); // Also min, because first value set using ur_copy_fields

/**
 *
 * @tparam T
 * @param src
 * @param dst
 */
template <typename T>
void last(const void *src, void *dst)
{
   *((T*)dst) = *((T*)src);
}

/**
 * Brief structure description
 */
typedef struct {
   void *dst;
    int field_id;
    int var_len;
} var_params;

/**
 *
 * @param src
 * @param dst
 */
void last_variable(const void *src, void *dst);

/**
 *
 * @tparam T
 * @param src
 * @param dst
 */
template <typename T>
void bitwise_or(const void *src, void *dst)
{
   *((T*)dst) |= *((T*)src);
}

/**
 *
 * @tparam T
 * @param src
 * @param dst
 */
template <typename T>
void bitwise_and(const void *src, void *dst)
{
   *((T*)dst) &= *((T*)src);
}

#endif //AGGREGATOR_AGG_FUNCTIONS_H