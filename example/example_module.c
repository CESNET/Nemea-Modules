/**
 * \file example_module.c
 * \brief Example of NEMEA module.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 * \date 2014
 */
/*
 * Copyright (C) 2013,2014 CESNET
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

//information if sigaction is available for nemea signal macro registration
//(TRAP_DEFAULT_INITIALIZATION)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

UR_FIELDS (
   uint32 BAR,
   uint32 FOO,
   uint32 BAZ
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Example module","This module serves as an example of module implementation in TRAP platform. It receives UniRec containing two numbers (FOO and BAR) and sends UniRec containing the same numbers and their sum (BAZ).",1,1)

#define MODULE_PARAMS(PARAM)

static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
// [Use either this macro or the code below, they're equivalent.]
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

int main(int argc, char **argv)
{
   int ret;

   // ***** TRAP initialization *****

   // Let TRAP library parse command-line arguments and extract its parameters
   // [Use either this macro or the code below, they're equivalent.]
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   // Register signal handler.
   // [Use either this macro or the code below, they're equivalent.]
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec templates *****
   ur_template_t *in_tmplt = ur_create_input_template(0, "FOO,BAR", NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }
   ur_template_t *out_tmplt = ur_create_output_template(0, "FOO,BAR,BAZ", NULL);
   if (out_tmplt == NULL){
      ur_free_template(in_tmplt);
      fprintf(stderr, "Error: Output template could not be created.\n");
      return -1;
   }
   // Allocate memory for output record
   void *out_rec = ur_create_record(out_tmplt, 0);
   if (out_rec == NULL){
      ur_free_template(in_tmplt);
      ur_free_template(out_tmplt);
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      return -1;
   }

   // ***** Main processing loop *****

   // Read data from input, process them and write to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set  using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      // Handle possible errors
      // [Use either this macro or the code below, they're equivalent.]
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA

      // Read FOO and BAR from input record and compute their sum
      uint32_t baz = ur_get(in_tmplt, in_rec, F_FOO) +
                     ur_get(in_tmplt, in_rec, F_BAR);

      // Fill output record
      ur_copy_fields(out_tmplt, out_rec, in_tmplt, in_rec);
      ur_set(out_tmplt, out_rec, F_BAZ, baz);

      // Send record to interface 0.
      // Block if ifc is not ready (unless a timeout is set using trap_ifcctl)
      ret = trap_send(0, out_rec, ur_rec_fixlen_size(out_tmplt));
      // Handle possible errors
      // [Use either this macro or the code below, they're equivalent.]
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
   }

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   // [Use either this macro or the code below, they're equivalent.]
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   /*
   trap_finalize();
   */
   ur_free_record(out_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   ur_finalize();

   return 0;
}

