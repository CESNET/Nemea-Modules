/**
 * \file timedb.c
 * \brief Time based round database
 * \author Miroslav Kalina <kalinmi2@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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

#include "timedb.h"

#include "fields.h"
#include <unirec/unirec.h>
#include <stdio.h>
#include <math.h>
#include <b_plus_tree.h>
#include <unirec/ipaddr.h>
#include <openssl/md5.h>

// -------- Useful definitions -------------

#ifndef min
#define min(a, b)  ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a, b)  ((a) > (b) ? (a) : (b))
#endif

#define rolling_data(timedb, i) (timedb)->data[((timedb)->data_begin + (i)) % (timedb)->size]

// -------- B+ TREE comparators -------------

#define COMPARATOR(type) \
   int compare_ ## type(void *a, void *b) \
   { \
      if (*(type *) a == *(type *) b) { \
         return EQUAL; \
      } \
      else if (*(type *) a < *(type *) b) { \
         return LESS; \
      } \
      else { \
         return MORE; \
      } \
   }

COMPARATOR(int8_t)
COMPARATOR(uint8_t)
COMPARATOR(int16_t)
COMPARATOR(uint16_t)
COMPARATOR(int32_t)
COMPARATOR(uint32_t)
COMPARATOR(int64_t)
COMPARATOR(uint64_t)
COMPARATOR(float)
COMPARATOR(double)
COMPARATOR(ur_time_t)

// or pass directly "(int(*)(void*,void*)) &ip_cmp" ??? it return strcmp instead of -1/0/1
int compare_ip_addr_t(void *a, void *b)
{
   int cmp = ip_cmp((ip_addr_t *) a, (ip_addr_t *) b);
   if (cmp == 0) {
      return EQUAL;
   } else if (cmp < 0) {
      return LESS;
   } else {
      return MORE;
   }
}

int compare_mac_addr_t(void *a, void *b)
{
   int cmp = mac_cmp((mac_addr_t *) a, (mac_addr_t *) b);
   if (cmp == 0) {
      return EQUAL;
   } else if (cmp < 0) {
      return LESS;
   } else {
      return MORE;
   }
}

int compare_md5(void *a, void *b)
{
   int cmp = memcmp((ip_addr_t *) a, (ip_addr_t *) b, 16);
   if (cmp == 0) {
      return EQUAL;
   } else if (cmp < 0) {
      return LESS;
   } else {
      return MORE;
   }
}

// -------- Helper functions -------------

char *get_md5_hash(const void * value, int value_size)
{
   MD5_CTX ctx;
   char *digest = (char *) calloc(16, sizeof(char));

   MD5_Init(&ctx);
   while (value_size > 0) {
      if (value_size > 512) {
         MD5_Update(&ctx, value, 512);
      } else {
         MD5_Update(&ctx, value, value_size);
      }
      value_size -= 512;
      value += 512;
   }

   MD5_Final((unsigned char *) digest, &ctx);

   return digest;
}

// -------- TimeDB main code -------------

timedb_t *timedb_create(int step, int delay, int inactive_timeout, int count_uniq)
{
   timedb_t *timedb = (timedb_t *) calloc(1, sizeof(timedb_t));

   timedb->step = step;
   timedb->size = delay / step + 2;
   timedb->inactive_timeout = inactive_timeout;
   timedb->data_begin = 0;
   timedb->initialized = 0;
   timedb->count_uniq = count_uniq > 0 ? 1 : 0;

   timedb->data = (time_series_t **) calloc(timedb->size, sizeof(time_series_t *));
   for (int i = 0; i < timedb->size; i++) {
      timedb->data[i] = (time_series_t *) calloc(1, sizeof(time_series_t));
   }

   return timedb;
}

// initialize timestamps by first inserted record
void timedb_init(timedb_t *timedb, time_t time)
{
   // round first begin to multiply of step
   time -= time % timedb->step;
   timedb->begin = time;

   for (int i = 0; i < timedb->size; i++) {
      timedb->data[i]->begin = time;
      time += timedb->step;
      timedb->data[i]->end = time;

      timedb->data[i]->sum = 0;
      timedb->data[i]->count = 0;
   }

   timedb->end = time;
}

// initialize timestamps by first inserted record
void timedb_init_tree(timedb_t *timedb, ur_field_type_t value_type)
{
   if (timedb->count_uniq == 1 && !timedb->initialized) { // count will be counted as unique values
      timedb->value_type = value_type;
      for (int i = 0; i < timedb->size; i++) {
         switch (timedb->value_type) {
            case UR_TYPE_CHAR:
            case UR_TYPE_UINT8:
               timedb->b_tree_compare = &compare_uint8_t;
               timedb->b_tree_key_size = 1;
               break;
            case UR_TYPE_INT8:
               timedb->b_tree_compare = &compare_int8_t;
               timedb->b_tree_key_size = 1;
               break;
            case UR_TYPE_UINT16:
               timedb->b_tree_compare = &compare_uint16_t;
               timedb->b_tree_key_size = 2;
               break;
            case UR_TYPE_INT16:
               timedb->b_tree_compare = &compare_int16_t;
               timedb->b_tree_key_size = 2;
               break;
            case UR_TYPE_UINT32:
               timedb->b_tree_compare = &compare_uint32_t;
               timedb->b_tree_key_size = 4;
               break;
            case UR_TYPE_INT32:
               timedb->b_tree_compare = &compare_int32_t;
               timedb->b_tree_key_size = 4;
               break;
            case UR_TYPE_FLOAT:
               timedb->b_tree_compare = &compare_float;
               timedb->b_tree_key_size = 4;
               break;
            case UR_TYPE_UINT64:
               timedb->b_tree_compare = &compare_uint64_t;
               timedb->b_tree_key_size = 8;
               break;
            case UR_TYPE_INT64:
               timedb->b_tree_compare = &compare_int64_t;
               timedb->b_tree_key_size = 8;
               break;
            case UR_TYPE_DOUBLE:
               timedb->b_tree_compare = &compare_double;
               timedb->b_tree_key_size = 8;
               break;
            case UR_TYPE_TIME:
               timedb->b_tree_compare = &compare_ur_time_t;
               timedb->b_tree_key_size = 8;
               break;
            case UR_TYPE_IP:
               timedb->b_tree_compare = &compare_ip_addr_t;
               timedb->b_tree_key_size = 16;
               break;
            case UR_TYPE_MAC:
               timedb->b_tree_compare = &compare_mac_addr_t;
               timedb->b_tree_key_size = 6;
               break;
            case UR_TYPE_STRING:
            case UR_TYPE_BYTES:
               timedb->b_tree_compare = &compare_md5;
               timedb->b_tree_key_size = 16;
               break;
         }
         timedb->data[i]->b_plus_tree = bpt_init(TIMEDB__B_PLUS_TREE__LEAF_ITEM_NUMBER, timedb->b_tree_compare, 0, timedb->b_tree_key_size);
      }
      timedb->initialized = 1;
   }
}

int timedb_save_data(timedb_t *timedb, ur_time_t urfirst, ur_time_t urlast, ur_field_type_t value_type, void *value_ptr, int var_value_size)
{
   // get first and last time seen
   time_t first_sec = ur_time_get_sec(urfirst);
   int first_msec = ur_time_get_msec(urfirst);

   time_t last_sec = ur_time_get_sec(urlast);
   int last_msec = ur_time_get_msec(urlast);

   // check initialized timedb
   if (!timedb->begin) {
      timedb_init(timedb, first_sec);
   }

   // check initialized B+ tree
   timedb_init_tree(timedb, value_type);

   // check inactive timeout
   if (first_sec-timedb->begin > timedb->inactive_timeout) {
      timedb_init(timedb, first_sec);
   }

   // get value and convert it into double
   double value;
   switch (value_type) {
      case UR_TYPE_INT8:
         value = *((int8_t *) value_ptr);
         break;
      case UR_TYPE_INT16:
         value = *((int16_t *) value_ptr);
         break;
      case UR_TYPE_INT32:
         value = *((int32_t *) value_ptr);
         break;
      case UR_TYPE_INT64:
         value = *((int64_t *) value_ptr);
         break;
      case UR_TYPE_UINT8:
         value = *((uint8_t *) value_ptr);
         break;
      case UR_TYPE_UINT16:
         value = *((uint16_t *) value_ptr);
         break;
      case UR_TYPE_UINT32:
         value = *((uint32_t *) value_ptr);
         break;
      case UR_TYPE_UINT64:
         value = *((uint64_t *) value_ptr);
         break;
      case UR_TYPE_FLOAT:
         value = *((float *) value_ptr);
         break;
      case UR_TYPE_DOUBLE:
         value = *((double *) value_ptr);
         break;
      default:
         if (timedb->count_uniq) {
            value = 0;
            if (value_type == UR_TYPE_STRING || value_type == UR_TYPE_BYTES) {
               // @TODO Shall we allow saving zero length UR_STRING and UR_BYTES ??? Or it should be ignored as empty = nothing ?
               //if (var_value_size <= 0) {
               //   fprintf(stderr, "Warning: Saving zero-length string into TimeDB.\n");
               //}
               value_ptr = get_md5_hash(value_ptr, var_value_size);
            }
         } else {
            fprintf(stderr, "Error: Trying to save unsupported value into TimeDB.\n");
            return TIMEDB_SAVE_ERROR;
         }
         break;
   }

   double value_per_sec = 1.0 * value / (1.0 * (last_sec - first_sec) + 1.0 * (last_msec - first_msec) / 1000 );

   // check if records ends too late, we need to rollout
   if (timedb->end < last_sec) {
      return TIMEDB_SAVE_NEED_ROLLOUT;
   }

   // add portion of value (bytes/packets) to every time window
   for (int i = 0; i < timedb->size; i++) {
      if(rolling_data(timedb, i)->begin <= last_sec && rolling_data(timedb, i)->end >= first_sec) {
         // get time in this time window
         // @TODO consider direct comparition using ur_time_t instead of time_t
         double time = min((double) (rolling_data(timedb, i)->end), 1.0 * last_sec + 1.0 * last_msec / 1000) - max((double) (rolling_data(timedb, i)->begin), 1.0 * first_sec + 1.0 * first_msec / 1000) ;

         // save portion of value in this time window
         if (value_per_sec == INFINITY) { // watchout zero length interval
            rolling_data(timedb, i)->sum += value;
         } else {
            rolling_data(timedb, i)->sum += value_per_sec * time;
         }

         if (timedb->count_uniq) { // we want to count only unique values
            void *item = bpt_search_or_insert(rolling_data(timedb, i)->b_plus_tree, value_ptr);
            if (item == NULL) {
               fprintf(stderr, "Error: Could not allocate leaf node of the B+ tree. Perhaps out of memory?\n");
               return TIMEDB_SAVE_ERROR;
            }
         } else {
            rolling_data(timedb, i)->count += 1;
         }
      }
   }

   // Free md5 hash if is was computed
   if (var_value_size > 0 && value_ptr) {
      free(value_ptr);
   }

   // check if record starts before database
   if (timedb->begin > first_sec) {
      //fprintf(stderr, "[timedb_save_data] Flow record truncated, because it starts earlier than database can handle now.\n");
      return TIMEDB_SAVE_FLOW_TRUNCATED;
   }

   return TIMEDB_SAVE_OK;
}

// get last value, roll database, fill variables *sum and *count
void timedb_roll_db(timedb_t *timedb, time_t *time, double *sum, uint32_t *count)
{
   // get data
   *time = rolling_data(timedb, 0)->begin;
   *sum = rolling_data(timedb, 0)->sum;
   if (timedb->count_uniq) {
      *count = (uint32_t) bpt_item_cnt(rolling_data(timedb, 0)->b_plus_tree);
   } else {
      *count = rolling_data(timedb, 0)->count;
   }

   // free time_serie before rolling
   rolling_data(timedb, 0)->begin = timedb->end;
   rolling_data(timedb, 0)->end = timedb->end + timedb->step;
   rolling_data(timedb, 0)->sum = 0;
   rolling_data(timedb, 0)->count = 0;
   if (timedb->count_uniq) {
      bpt_clean(rolling_data(timedb, 0)->b_plus_tree);
      rolling_data(timedb, 0)->b_plus_tree = bpt_init(TIMEDB__B_PLUS_TREE__LEAF_ITEM_NUMBER, timedb->b_tree_compare, 0, timedb->b_tree_key_size);
   }

   // jump step forward
   timedb->begin += timedb->step;
   timedb->end += timedb->step;
   timedb->data_begin = (timedb->data_begin + 1) % timedb->size;
}

void timedb_free(timedb_t *timedb)
{
   if (timedb) {
      if (timedb->data) {
         for (int i = 0; i < timedb->size; i++) {
            if (timedb->data[i]->b_plus_tree) {
               bpt_clean(timedb->data[i]->b_plus_tree);
            }
            free(timedb->data[i]);
         }
         free(timedb->data);
      }
      free(timedb);
   }
}
