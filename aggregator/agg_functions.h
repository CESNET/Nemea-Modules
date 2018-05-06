/**
 * \file agg_functions.h
 * \brief Aggregation functions available for use in module.
 * \author Michal Slabihoudek <slabimic@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include <unirec/unirec.h>

#ifndef AGGREGATOR_AGG_FUNCTIONS_H
#define AGGREGATOR_AGG_FUNCTIONS_H

/**
 * Makes sum of values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
void sum(const void *src, void *dst)
{
   *((T*)dst) += *((T*)src);
}

/**
 * Makes sum of values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
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
 * Makes average of value stored on src pointer and count from given type T.
 * @tparam T template type variable.
 * @param [in,out] src pointer to data which will be modified to fill the average value.
 * @param [in] count of received record (divider of sum).
 */
template <typename T>
void make_avg(void *src, uint32_t count)
{
   *((T*)src) /= count;
}

/**
 * Store min value from values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
void min(const void *src, void *dst)
{
   if (*((T*)src) < *((T*)dst))
      *((T*)dst) = *((T*)src);

}

/**
 * Store min value from values stored on src and dst pointers of type ip_addr_t.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
void min_ip(const void *src, void *dst);

/**
 * Store max value from values stored on src and dst pointers from given type T.
 * @tparam T
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
void max(const void *src, void *dst)
{
   if (*((T*)src) > *((T*)dst))
      *((T*)dst) = *((T*)src);

}

/**
 * Store max value from values stored on src and dst pointers of type ip_addr_t
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
void max_ip(const void *src, void *dst);

/**
 * Nope function used as first aggregation function and other function which has to do nothing.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
void nope(const void *src, void *dst); // Also min, because first value set using ur_copy_fields

/**
 * Update currently stored value of dst pointer with one from src pointer of given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
void last(const void *src, void *dst)
{
   *((T*)dst) = *((T*)src);
}

/**
 * Structure to pass data needed by new thread for different timeout types checking.
 */
typedef struct {
   void *dst;
    int field_id;
    int var_len;
} var_params;

/**
 * Update currently stored value of dst pointer with one from src pointer of variable length field.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
void last_variable(const void *src, void *dst);

/**
 * Store bitwise OR value from values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
void bitwise_or(const void *src, void *dst)
{
   *((T*)dst) |= *((T*)src);
}

/**
 *Store bitwise AND value from values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
void bitwise_and(const void *src, void *dst)
{
   *((T*)dst) &= *((T*)src);
}

#endif //AGGREGATOR_AGG_FUNCTIONS_H