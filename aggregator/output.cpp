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
int OutputTemplate::indexes_to_record [MAX_KEY_FIELDS];
int OutputTemplate::sizes_of_fields [MAX_KEY_FIELDS];
void (OutputTemplate::process[MAX_KEY_FIELDS]);
uint OutputTemplate::used_fields = 0;
bool OutputTemplate::prepare_to_send = false;
bool OutputTemplate::avg_fields[MAX_KEY_FIELDS];

/* ----------------------------------------------------------------- */
void OutputTemplate::add_field(int record_id, int size, agg_func foo, bool avg)
{
   indexes_to_record[used_fields] = record_id;
   sizes_of_fields[used_fields] = size;
   process[used_fields] = foo;
   avg_fields[used_fields] = avg;
   // If avg used for the first time set prepare_to_send flag
   if (!prepare_to_send && avg) {
      prepare_to_send = true;
   }
   used_fields++;
}
/* ----------------------------------------------------------------- */
