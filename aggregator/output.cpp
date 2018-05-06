/**
 * \file output.cpp
 * \brief Output template representation.
 * \author Michal Slabihoudek <slabimic@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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
agg_func (OutputTemplate::process[MAX_KEY_FIELDS]);
int OutputTemplate::used_fields = 0;
bool OutputTemplate::prepare_to_send = false;
final_avg OutputTemplate::avg_fields[MAX_KEY_FIELDS];

/* ----------------------------------------------------------------- */
void OutputTemplate::add_field(int record_id, agg_func foo, bool avg, final_avg foo2)
{
   indexes_to_record[used_fields] = record_id;
   process[used_fields] = foo;
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
