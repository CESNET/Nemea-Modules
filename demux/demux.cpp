/**
 * \file demux.cpp
 * \brief Recover united interfaces (by mux module) to single streams.
 * \author Dominik Soukup <soukudom@fit.cvut.cz>
 * \date 1/2018
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <unirec/unirec.h>
#include <libtrap/trap.h>
#include <signal.h>
#include <getopt.h>

using namespace std;

typedef struct meta_info_s {
    uint16_t messageID; //1 - normal data, 2 - hello message (unirec fmt changed)
    uint16_t interfaceID;
    uint8_t data_fmt;
    char payload [0];
} meta_info_t;

int HEADER_SIZE = 5;
int exit_value = 0;
static ur_template_t **out_templates = NULL; //UniRec output templates
static int n_outputs = 0;
trap_ctx_t *ctx = NULL;
int stop = 0;
int ret = 0;
const void *data_nemea_output = NULL;
uint16_t memory_received = 0;
int verbose = 0;

//struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("demux", "This module splits united input to more outputs", 1, -1)
#define MODULE_PARAMS(PARAM) \
PARAM('n', "link_count", "Sets count of output links. Must correspond to parameter -i (trap).", required_argument, "int32")


int main (int argc, char ** argv)
{
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   trap_ifc_spec_t ifc_spec;
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(module_info);
         return 0;
      }
      cerr << "ERROR in parsing of parameters for TRAP: " << trap_last_error_msg << endl;
      return 1;
   }

   //parse remaining parameters and get configuration
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'n':
         n_outputs = atoi(optarg);
         break;
      default:
        cerr <<  "Error: Invalid arguments." << endl;
        exit_value = 1;
        goto cleanup;
      }
    }

   verbose = trap_get_verbose_level();
   if (verbose >= 0) {
      cout << "Verbosity level: " <<  trap_get_verbose_level();
   }

   if (verbose >= 0) {
      cout << "Number of outputs: " << n_outputs << endl;
   }
   if (n_outputs < 1) {
      cerr << "Error: Number of output interfaces must be positive integer." << endl;
      exit_value = 2; 
      goto cleanup;
   }
   if (n_outputs > 32) {
      cerr << "Error: More than 32 interfaces is not allowed by TRAP library." << endl;
        
      exit_value = 2;
      goto cleanup;
   }

   //set number of output interfaces
   module_info->num_ifc_out = n_outputs;

   if (verbose >= 0) {
      cout << "Initializing TRAP library ..." << endl;
   }

   ctx = trap_ctx_init(module_info, ifc_spec);

   if (ctx == NULL) {
      cerr << "ERROR in TRAP initialization: " << trap_last_error_msg << endl;
      exit_value = 3;
      goto cleanup;
   }

   if (trap_ctx_get_last_error(ctx) != TRAP_E_OK){
      cerr << "ERROR in TRAP initialization: " << trap_ctx_get_last_error_msg(ctx) << endl;
      exit_value = 3;
      goto cleanup;
   }

   //check if number of interfaces is correct
   if (strlen(ifc_spec.types) <= 1) {
      cerr << "ERROR expected at least 1 input and 1 output interface. Got only 1." << endl;
      exit_value = 2;
      goto cleanup;
   }

   //input interface control settings
   if (trap_ctx_ifcctl(ctx, TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_WAIT) != TRAP_E_OK) {
      cerr << "ERROR in input interface initialization" << endl;
      exit_value = 3;
      goto cleanup;
   }

   //allocate memory for output templates
   out_templates = (ur_template_t **) calloc(n_outputs, sizeof(*out_templates));
   if (out_templates == NULL) {
      cerr <<  "Memory allocation error." << endl;
      exit_value = 3;
      goto cleanup;
   }

   //initialize and set templates for UniRec negotiation
   for (int i = 0; i < n_outputs; i++) {
      //output interfaces control settings
      if (trap_ctx_ifcctl(ctx, TRAPIFC_OUTPUT, i, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT) != TRAP_E_OK) {
         cerr << "ERROR in output interface initialization" << endl;
         exit_value = 3;
         goto cleanup;
      }
      //create empty output template
      out_templates[i] = ur_ctx_create_output_template(ctx, i, NULL, NULL);
      if (out_templates[i] == NULL) {
         cerr << "Memory allocation error." << endl;
         exit_value = 3;
         goto cleanup;
      }
      //set format for output interfaces
      trap_ctx_set_data_fmt(ctx, i, TRAP_FMT_UNIREC, NULL);
   }

   //set required incoming format
   trap_ctx_set_required_fmt(ctx, 0, TRAP_FMT_RAW);

   //main loop
   while (!stop) {
      ret = trap_ctx_recv(ctx, 0, &data_nemea_output, &memory_received);
      //process received data
      meta_info_t *ptr = (meta_info_t *) data_nemea_output;

      //set new template
      if (ptr->messageID == 2) {
         if (verbose >= 0) {
            cout << "Hello message has been received. Setting data format for the output interface with index " << ptr->interfaceID << endl;
         }
         trap_ctx_set_data_fmt(ctx, ptr->interfaceID, ptr->data_fmt, (((char *) (data_nemea_output) + 5)));
      } else if (ptr->messageID == 1) {
         //forward data to the appropriate interface
         if (verbose >= 0) {
            cout << "Normal data message has been received. Forwarding to the output interface with index " << ptr->interfaceID << endl;
         }
         //send only payload data
         ret = trap_ctx_send(ctx, ptr->interfaceID, ptr->payload, memory_received-HEADER_SIZE);
      } else {
         cerr << "ERROR: Received message is not valid!" << endl;
      }
   }

cleanup:
    //cleaning
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
    trap_ctx_finalize(&ctx);
    return exit_value;
}
