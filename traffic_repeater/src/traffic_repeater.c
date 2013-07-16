/*!
 * \file traffic_repeater.c
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
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

#include "traffic_repeater.h"

void signal_handler(int signal)
{
   if ((signal == SIGTERM) || (signal == SIGINT)) {
      VERBOSE(CL_VERBOSE_OFF, "Signal termination or interrupt received.\n");
      stop = 1;
      trap_terminate();
   }
}


void module_init(trap_module_info_t *module, int ifc_in, int ifc_out)
{
   char buffer[BUFFER_TMP];
   
   memset(buffer, 0, BUFFER_TMP);
   module->name = "Traffic repeater";  
   module->description = "This module receive data from input interface and resend it to the output interface "
                         "based on given arguments in -i option";
   module->num_ifc_in = ifc_in;
   module->num_ifc_out = ifc_out;
}

int repeater_init(trap_module_info_t *module_info, trap_ifc_spec_t *ifc_spec) 
{ 
   verbose = CL_VERBOSE_OFF;
   VERBOSE(CL_VERBOSE_OFF, "Initializing traffic repeater...");
   
   if (trap_init(module_info, *ifc_spec) != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      trap_finalize();
      return EXIT_FAILURE;
   }
   
   traffic_repeater();
   trap_finalize();
   return EXIT_SUCCESS;
}

void traffic_repeater(void)
{
   int ret, timeout;
   uint16_t data_size;
   uint64_t cnt_r, cnt_s, cnt_t;
   time_t start, end;
   double diff;
   const void *data;

   data_size = 0;
   cnt_r = cnt_s = cnt_t = 0;
   data = NULL;
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);

   timeout = TRAP_WAIT;
   time(&start);
   
   while (stop == 0) {
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, timeout);
      if (ret == TRAP_E_OK) {
         cnt_r++;
         if (data_size == 1) {
            VERBOSE(CL_VERBOSE_OFF, "Final record received, terminating repeater...");
            stop = 1;
         }          
         ret = trap_send_data(0, data, data_size, timeout);
         if (ret == TRAP_E_OK) {
            cnt_s++;
            continue;
         } else if (ret == TRAP_E_TERMINATED) {
            fprintf(stderr, "ERROR in sending, TRAP terminated.\n");
            break;
         } else if (ret == TRAP_E_TIMEOUT) {
             fprintf(stderr, "ERROR in sending, TRAP timeout.\n"); 
             cnt_t++;
             continue;
         } else {
            fprintf(stderr, "ERROR %s\n", trap_last_error_msg);
            break;
	     }
      } else if (ret == TRAP_E_TERMINATED) {
          fprintf(stderr, "ERROR in receiving, TRAP terminated.\n");
          break;
      } else if (ret == TRAP_E_IO_ERROR) {
          fprintf(stderr, "ERROR in receiving, IO error in TRAP.\n");
          break;
      } else if (ret == TRAP_E_TIMEOUT) {
          fprintf(stderr, "ERROR in receiving, TRAP timeout.\n"); 
          cnt_t++;
          continue;
      } else {
         fprintf(stderr, "ERROR %s\n", trap_last_error_msg);
         break;
      }    
   }
   
   time(&end);
   diff = difftime(end, start);
   printf("RECV: %lu\nSENT: %lu\nTOUT: %lu\nTIME: %.3fs\n", cnt_r, cnt_s, cnt_t, diff);
}

int main(int argc, char **argv)
{
   int ret;
   char usage[BUFFER_TMP];
   trap_ifc_spec_t ifc_spec;
   trap_module_info_t module_info;
   
   module_init(&module_info, IFC_DEF, IFC_DEF);
   snprintf(usage, BUFFER_TMP, "Usage: %s [-h] [-v] [-vv] [-vvv] -i IFC_SPEC\n", argv[0]);
   
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) {
         trap_print_help(&module_info);
         return EXIT_SUCCESS;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      trap_finalize();
      fprintf(stderr, "%s", usage);
      return EXIT_FAILURE;
   }
   
   if (argc != 1) {
      trap_finalize();
      fprintf(stderr, "%s", usage);
      return EXIT_FAILURE;
   }
   
   if (repeater_init(&module_info, &ifc_spec))
      return EXIT_FAILURE;
   
   return EXIT_SUCCESS;
}
