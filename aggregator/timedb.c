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


#ifndef min
#define min(a, b)  ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a, b)  ((a) > (b) ? (a) : (b))
#endif

#define rolling_data(timedb, i) (timedb)->data[((timedb)->data_begin + (i)) % (timedb)->size]

timedb_t * timedb_create(int step, int delay)
{
   timedb_t * timedb = (timedb_t *) calloc(1, sizeof(timedb_t));
   
   timedb->step = step;
   timedb->size = delay/step + 2;
   timedb->data_begin = 0;

   timedb->data = (time_series_t **) calloc(timedb->size, sizeof(time_series_t *));
   for (int i=0; i<timedb->size; i++) {
      timedb->data[i] = (time_series_t *) calloc(1, sizeof(time_series_t));
   }
   
   return timedb;
}

// initialize timestamps by first inserted record
void timedb_init(timedb_t *timedb, time_t time) {
   // round first begin to multiply of step
   time -= time % timedb->step;
   timedb->begin = time;
   
   for (int i=0; i<timedb->size; i++) {
      timedb->data[i]->begin = time;
      time += timedb->step;
      timedb->data[i]->end = time;
      
      timedb->data[i]->sum = 0;
      timedb->data[i]->count = 0;
   }
   
   timedb->end = time;
}

int timedb_save_data(timedb_t *timedb, ur_time_t urfirst, ur_time_t urlast, uint64_t value)
{
   // get first and last time seen
   time_t first_sec = ur_time_get_sec(urfirst);
   int first_msec = ur_time_get_msec(urfirst);

   time_t last_sec = ur_time_get_sec(urlast);
   int last_msec = ur_time_get_msec(urlast);
   
   // calculate unified value per 1 sec
   double value_per_sec = 1.0*value / (1.0*(last_sec-first_sec) + 1.0*(last_msec-first_msec)/1000 );

   // check initialized timedb
   if (!timedb->begin) {
      timedb_init(timedb, first_sec);
   }
   
   // check if records ends too late, we need to rollout
   if (timedb->end < last_sec) {
      return TIMEDB_SAVE_NEED_ROLLOUT;
   }
   
   // add portion of value (bytes/packets) to every time window
   for (int i=0; i<timedb->size; i++) {
      if(rolling_data(timedb, i)->begin <= last_sec && rolling_data(timedb, i)->end >= first_sec) {
         // get time in this time window
         // @TODO consider direct comparition using ur_time_t instead of time_t
         double time = min((double)(rolling_data(timedb, i)->end), 1.0*last_sec+1.0*last_msec/1000) - max((double)(rolling_data(timedb, i)->begin), 1.0*first_sec+1.0*first_msec/1000) ;

         // save portion of value in this time window
         if (value_per_sec == INFINITY) { // watchout zero length interval
            rolling_data(timedb, i)->sum += value;
         }
         else {
            rolling_data(timedb, i)->sum += (long) (value_per_sec * time);
         }
         rolling_data(timedb, i)->count += 1;
      }
   }
   
   // check if record starts before database
   if (timedb->begin > first_sec) {
      fprintf(stderr, "[timedb_save_data] Flow record truncated, because it starts earlier than database can handle now.\n");
      return TIMEDB_SAVE_FLOW_TRUNCATED;
   }

   return TIMEDB_SAVE_OK;
}

// get last value, roll database, fill variables *sum and *count
void timedb_roll_db(timedb_t * timedb, time_t *time, uint64_t *sum, uint32_t *count)
{
   // get data
   *time = rolling_data(timedb, 0)->begin;
   *sum = rolling_data(timedb, 0)->sum;
   *count = rolling_data(timedb, 0)->count;
   
   // free time_serie before rolling
   rolling_data(timedb, 0)->begin = timedb->end;
   rolling_data(timedb, 0)->end = timedb->end + timedb->step;
   rolling_data(timedb, 0)->sum = 0;
   rolling_data(timedb, 0)->count = 0;

   // jump step forward
   timedb->begin += timedb->step;
   timedb->end += timedb->step;
   timedb->data_begin = (timedb->data_begin + 1) % timedb->size;
}

void timedb_free(timedb_t * timedb)
{
   if (timedb) {
      if (timedb->data) {
         for (int i=0; i<timedb->size; i++) {
            free(timedb->data[i]);
         }
      }
      free(timedb->data);
      free(timedb);
   }
}
