//
// Created by slabimic on 24/02/18.
//

#ifndef AGGREGATOR_OUTPUT_H
#define AGGREGATOR_OUTPUT_H


#include "key.h"
#include "agg_functions.h"

typedef void (*agg_func)(const void *src, void *dst);    // Define pointer to agg function as a data type

class OutputTemplate {
public:
   static ur_template_t *out_tmplt;
   static int indexes_to_record[MAX_KEY_FIELDS];
   //static int sizes_of_fields[MAX_KEY_FIELDS];
   static int used_fields;
   //static void (*agg_func[MAX_KEY_FIELDS])(const void *src, void *dst);
   static agg_func process[MAX_KEY_FIELDS];
   static bool prepare_to_send;
   static bool avg_fields[MAX_KEY_FIELDS];

   static void add_field(int record_id, agg_func foo, bool avg_flag);
};

#endif //AGGREGATOR_OUTPUT_H