//
// Created by slabimic on 24/02/18.
//

#include "output.h"

/*
*  class definitions
*/
/* ================================================================= */
/* ============= OutputTemplate class initializations ================= */
/* ================================================================= */

/*
 * Static variables declaration, better than global variable
 */
ur_template_t *OutputTemplate::out_tmplt = NULL;
int OutputTemplate::indexes_to_record [MAX_KEY_FIELDS];
//int OutputTemplate::sizes_of_fields [MAX_KEY_FIELDS];
agg_func (OutputTemplate::process[MAX_KEY_FIELDS]);
int OutputTemplate::used_fields = 0;
bool OutputTemplate::prepare_to_send = false;
//bool OutputTemplate::avg_fields[MAX_KEY_FIELDS];
final_avg OutputTemplate::avg_fields[MAX_KEY_FIELDS];

/* ----------------------------------------------------------------- */
void OutputTemplate::add_field(int record_id, agg_func foo, bool avg, final_avg foo2)
{
   indexes_to_record[used_fields] = record_id;
   //sizes_of_fields[used_fields] = size;
   process[used_fields] = foo;
   //avg_fields[used_fields] = avg;
   avg_fields[used_fields] = foo2;
   // If avg used for the first time set prepare_to_send flag
   if (!prepare_to_send && avg) {
      prepare_to_send = true;
   }
   used_fields++;
}
/* ----------------------------------------------------------------- */
void OutputTemplate::reset()
{
   prepare_to_send = false;
   used_fields = 0;
   ur_free_template(out_tmplt);
}
/* ----------------------------------------------------------------- */
