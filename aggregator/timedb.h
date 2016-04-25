/**
 * \file timedb.h
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

#ifndef TIMEDB_H
#define TIMEDB_H

#include <time.h>
#include <inttypes.h>
#include <unirec/unirec.h>
#include <b_plus_tree.h>

// ------- CONFIGURATION -----------

#define TIMEDB__B_PLUS_TREE__LEAF_ITEM_NUMBER 8

// -------- DEFINITIONS ------------

#define TIMEDB_SAVE_ERROR -1
#define TIMEDB_SAVE_OK 0
#define TIMEDB_SAVE_NEED_ROLLOUT 1
#define TIMEDB_SAVE_FLOW_TRUNCATED 2

typedef struct time_series_s {
    time_t begin;
    time_t end;
    double sum;
    uint32_t count;
    void *b_plus_tree;
} time_series_t;

typedef struct timedb_s {
   int step;
   int size;
   int inactive_timeout;
   time_t begin;
   time_t end;
   time_series_t **data;
   int data_begin;
   ur_field_type_t value_type;
   int count_uniq;
   int (*b_tree_compare) (void *, void *);
   int b_tree_key_size;
   uint8_t initialized;
} timedb_t;

timedb_t * timedb_create(int step, int delay, int inactive_timeout, int count_uniq);

void timedb_init(timedb_t *timedb, time_t first);

void timedb_init_tree(timedb_t *timedb, ur_field_type_t value_type);

int timedb_save_data(timedb_t *timedb, ur_time_t urfirst, ur_time_t urlast, ur_field_type_t value_type, void * value);

void timedb_roll_db(timedb_t *timedb, time_t *time, double *sum, uint32_t *count);

void timedb_free(timedb_t *timedb);

#endif /* TIMEDB_H */
