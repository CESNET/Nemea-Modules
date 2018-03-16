/*! \file output.h
 */
//
// Created by slabimic on 24/02/18.
//

#ifndef AGGREGATOR_OUTPUT_H
#define AGGREGATOR_OUTPUT_H


#include "key.h"
#include "agg_functions.h"

/**
 *
 */
typedef void (*agg_func)(const void *src, void *dst);    // Define pointer to agg function as a data type
/**
 *
 */
typedef void (*final_avg)(void *record, uint32_t count);     // Define pointer to make_avg function template

/**
 *
 */
class OutputTemplate {
public:
   static ur_template_t *out_tmplt;                   /*!< Variable brief description. */
   static int indexes_to_record[MAX_KEY_FIELDS];      /*!< Variable brief description. */
   static int used_fields;                            /*!< Variable brief description. */
   static agg_func process[MAX_KEY_FIELDS];           /*!< Variable brief description. */
   static bool prepare_to_send;                       /*!< Variable brief description. */
   static final_avg avg_fields[MAX_KEY_FIELDS];       /*!< Variable brief description. */

   /**
    *
    * @param record_id
    * @param foo
    * @param avg_flag
    * @param foo2
    */
   static void add_field(int record_id, agg_func foo, bool avg_flag, final_avg foo2);
   /**
    *
    */
   static void reset();
};

#endif //AGGREGATOR_OUTPUT_H