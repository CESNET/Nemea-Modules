//
// Created by slabimic on 24/02/18.
//

#include <unirec/unirec.h>

#ifndef AGGREGATOR_AGG_FUNCTIONS_H
#define AGGREGATOR_AGG_FUNCTIONS_H


template <typename T>
void sum(const void *src, void *dst)
{
   *((T*)dst) += *((T*)src);
}

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
template <typename T>
void make_avg(void *src, uint32_t count)
{
   *((T*)src) /= count;
}

template <typename T>
void min(const void *src, void *dst)
{
   if (*((T*)src) < *((T*)dst))
      *((T*)dst) = *((T*)src);

}
void min_ip(const void *src, void *dst);

template <typename T>
void max(const void *src, void *dst)
{
   if (*((T*)src) > *((T*)dst))
      *((T*)dst) = *((T*)src);

}
void max_ip(const void *src, void *dst);


void nope(const void *src, void *dst); // Also min, because first value set using ur_copy_fields

template <typename T>
void last(const void *src, void *dst)
{
   *((T*)dst) = *((T*)src);
}


typedef struct {
   void *dst;
    int field_id;
    int var_len;
} var_params;

void last_variable(const void *src, void *dst);

template <typename T>
void bitwise_or(const void *src, void *dst)
{
   *((T*)dst) |= *((T*)src);
}

template <typename T>
void bitwise_and(const void *src, void *dst)
{
   *((T*)dst) &= *((T*)src);
}

#endif //AGGREGATOR_AGG_FUNCTIONS_H