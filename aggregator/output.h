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
 * Aggregation function pointer type definition.
 * Define pointer do aggregation function as a data type.
 */
typedef void (*agg_func)(const void *src, void *dst);
/**
 * Postprocessing average function pointer type definition.
 * Define pointer to make_avg function template.
 */
typedef void (*final_avg)(void *record, uint32_t count);

/**
 * Class to represent template for output records and its fields processing.
 */
class OutputTemplate {
public:
   static ur_template_t *out_tmplt;                   /*!< Output UniRec template pointer. */
   static int indexes_to_record[MAX_KEY_FIELDS];      /*!< Field index from global unirec structure. */
   static int used_fields;                            /*!< Count of stored and set fields in template. */
   static agg_func process[MAX_KEY_FIELDS];           /*!< Pointer to aggregation function of field data type. */
   static bool prepare_to_send;                       /*!< Flag is record postprocessing required by assigned aggregation function. */
   static final_avg avg_fields[MAX_KEY_FIELDS];       /*!< Pointer to postprocessing function for average function of field data type. */

   /**
    * Assign field with all required parameters to template.
    * @param [in] record_id index of field from global unirec structure.
    * @param [in] foo pointer to aggregation function of field with given record_id.
    * @param [in] avg_flag whether the field has avg function assigned.
    * @param [in] foo2 pointer to postprocessing average function or NULL instead.
    */
   static void add_field(int record_id, agg_func foo, bool avg_flag, final_avg foo2);
   /**
    * Reset all fields to default (empty) state.
    */
   static void reset();
};

#endif //AGGREGATOR_OUTPUT_H