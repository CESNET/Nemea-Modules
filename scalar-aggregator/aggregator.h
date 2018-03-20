/**
 * \file aggregator.c
 * \brief
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

#ifndef AGGREGATOR_H
#define AGGREGATOR_H

#include <stdint.h>

#include <unirec/unirec.h>
#include "../unirecfilter/lib/liburfilter.h"
#include "timedb.h"

// types of aggregation function
typedef enum {
   AGG_SUM,
   AGG_AVG,
   AGG_COUNT,
   AGG_RATE,
   AGG_COUNT_UNIQ
} agg_function;

// aggregation rule structure
typedef struct rule_s {
   char *name;
   urfilter_t *filter;
   agg_function agg;
   char *agg_arg;
   ur_field_type_t agg_arg_field;
   timedb_t *timedb;
} rule_t;

void rule_init(rule_t *rule, ur_template_t *tpl, const void *data);
rule_t *rule_create(const char *specifier, int step, int size, int inactive_timeout);
void rule_destroy(rule_t *object);

// output interface structure
typedef struct output_s {
   int interface;
   ur_template_t *tpl;
   void *out_rec;
   rule_t **rules;
   int rules_count;
} output_t;

output_t *create_output(int interface);
void destroy_output(output_t *object);

// internal functions
int flush_aggregation_counters();

// public interface - suppose to be empty

#endif /* AGGREGATOR_H */

