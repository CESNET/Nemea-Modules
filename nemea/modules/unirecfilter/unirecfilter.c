/**
 * \file unirecfilter.c
 * \brief NEMEA module selecting records and sending specified fields.
 * \author Klara Drhova <drhovkla@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
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

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "parser.tab.h"
#include "unirecfilter.h"

// Struct with information about module
trap_module_info_t module_info = {
   "Unirecfilter module",  // Module name
   // Module description
   "This NEMEA module selects records according to parameters in filter and sends\n"
   "only fields specified in output template.\n"
   "Unirecfilter expects unirec format of messages on input. Output format is\n"
   "specified with -O flag, input format specified with -I flag.\n"
   "Filter is specified with -F flag and contains expressions (<=, ==, &&, ...).\n"
   "You can also specify output format and filter in a FILE. Format of the file is\n"
   "TMPLT:FLTR or only :FLTR or TMPLT: on the first line.\n"
   "When is -O flag missing, template from input is used on output."
   "\n"
   "Usage:\n"
   "   ./unirecfilter -i IFC_SPEC -I TMPLT [-O TMPLT] [-F FLTR]\n"
   "   ./unirecfilter -i IFC_SPEC -I TMPLT [-f FILE]\n"
   "\n"
   "Parameters:\n"
   "   -I TMPLT       Specify UniRec template expected on the input interface.\n"
   "   -O TMPLT       Specify UniRec template expected on the output interface.\n"
   "   -F FLTR        Specify filter.\n"
   "   -f FILE        Read template and filter from FILE.\n"
   "   -c N           Quit after N records are received.\n"
   "\n"
   "Interfaces:\n"
   "   Inputs: 1\n"
   "   Outputs: 1\n",
   1,       // Number of input interfaces
   1,       // Number of output interfaces
};

static int stop = 0;

unsigned int num_records = 0; // Number of records received (total of all inputs)
unsigned int max_num_records = 0; // Exit after this number of records is received

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * \brief Get UniRec specifier part of argument
 * \param[in] str    is in following format: "<unirec spec>[:<filter>]"
 * \return copy of string, UniRec specifier of output IFC; NULL on failure
 */
char *getOutputSpec(const char *str)
{
   char *p = NULL;
   int l = strlen(str);
   char *OutS = NULL;
   p = strchr(str, SPEC_COND_DELIM);
   if (p == NULL) {
      /* not found */
      return strdup(str);
   } else {
      OutS = (char *) calloc(p - str + 1, 1);
      if (OutS != NULL) {
         strncpy(OutS, str, p - str);
      }
      return OutS;
   }
}

int main(int argc, char **argv)
{
   char *unirec_output_specifier = NULL;
   char *unirec_output = NULL;
   char *unirec_input_specifier = NULL;
   char *filter = NULL;
   char *file = NULL;
   ur_template_t *in_tmplt;
   ur_template_t *out_tmplt;
   void *out_rec;
   char opt;
   int ret;
   int from = 0; // 0 - template and filter from CMD, 1 - from file
   int memory_needed = 0;
   ur_field_id_t field_id = UR_INVALID_FIELD;
   struct ast * tree = NULL;

   // ***** TRAP initialization *****
   // Let TRAP library parse command-line arguments and extract its parameters
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   // Parse command-line options
   while ((opt = getopt(argc, argv, "I:O:F:f:c:")) != -1) {
      switch (opt) {
      case 'I':
         unirec_input_specifier = optarg;
         break;
      case 'O':
         unirec_output_specifier = optarg;
         break;
      case 'F': //Filter
         filter = optarg;
         break;
      case 'f':
         file = optarg;
         break;
      case 'c': {
         int nb = atoi(optarg);
         if (nb <= 0) {
            fprintf(stderr, "Error: Parameter of -c option must be > 0.\n");
            // Do all necessary cleanup before exiting
            TRAP_DEFAULT_FINALIZATION();
            return 3;
         }
         max_num_records = nb;
         break;
      }
      default:
         fprintf(stderr, "Error: Invalid arguments.\n");
         // Do all necessary cleanup before exiting
         TRAP_DEFAULT_FINALIZATION();
         return 4;
      }
   }

   // Input format specifier is missing
   if (unirec_input_specifier == NULL) {
      fprintf(stderr, "Error: Invalid arguments - no input specifier.\n");
      // Do all necessary cleanup before exiting
      TRAP_DEFAULT_FINALIZATION();
      return 5;
   } else {
      // Create UniRec input template
      in_tmplt = ur_create_template(unirec_input_specifier);
   }

   // Output format specifier and file are both set (-O and -f)
   if ((unirec_output_specifier != NULL) && (file != NULL)) {
      fprintf(stderr, "Error: Invalid arguments - two output specifiers.\n");
      // Do all necessary cleanup before exiting
      TRAP_DEFAULT_FINALIZATION();
      return 6;
   }
   // Filter and file are both set (-F and -f)
   else if ((filter != NULL) && (file != NULL)) {
      fprintf(stderr, "Error: Invalid arguments - two filters.\n");
      // Do all necessary cleanup before exiting
      TRAP_DEFAULT_FINALIZATION();
      return 6;
   }
   // Output format specifier and filter are in a file
   if (file != NULL) {
      FILE *f = fopen(file, "rt");
      // File cannot be opened / not found
      if (!f) {
         fprintf(stderr, "Error: File %s could be opened.\n", file);
         // Do all necessary cleanup before exiting
         TRAP_DEFAULT_FINALIZATION();
         return 7;
      }
      from = 1;
      unirec_output = (char *) calloc (1000,sizeof(char));
      if (!fgets(unirec_output, 1000, f)) {
         fprintf(stderr, "Error: File %s could not be read.\n", file);
         // Do all necessary cleanup before exiting
         TRAP_DEFAULT_FINALIZATION();
      }
      // no newline on the end of string
      unirec_output[strlen(unirec_output)-1] = 0;
      fclose(f);

      // Get output format specifier
      if (!(unirec_output_specifier = getOutputSpec(unirec_output))) {
         fprintf(stderr, "Error: Not enough space.\n");
         // Do all necessary cleanup before exiting
         TRAP_DEFAULT_FINALIZATION();
         return 8;
      }
   }
   // Get Abstract syntax tree from filter
   if (from == 1) { // From File
      tree = getTree(unirec_output);
   } else { // From CMD
      tree = getTree(filter);
   }

   // Create UniRec output template and record
   if (unirec_output_specifier && unirec_output_specifier[0] != '\0') { // Not NULL or Empty
      out_tmplt = ur_create_template(unirec_output_specifier);
   } else { //output template == input template
      out_tmplt = ur_create_template(unirec_input_specifier);
   }
   // calculate maximum needed memory for dynamic fields
   while ((field_id = ur_iter_fields(out_tmplt, field_id)) != UR_INVALID_FIELD) {
      if (ur_is_dynamic(field_id)) {
         memory_needed += DYN_FIELD_MAX_SIZE;
      }
   }
   out_rec = ur_create(out_tmplt, memory_needed);

   /* main loop */
   // Copy data from input to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from any input interface, wait until data are available
      ret = trap_recv(0, &in_rec, &in_rec_size);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_static_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break;   // End of data (used for testing purposes)
         } else {
            fprintf(stderr,
               "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
               ur_rec_static_size(in_tmplt),
               in_rec_size);
            break;
         }
      }
      // PROCESS THE DATA

      if (!tree || (tree && evalAST(tree, in_tmplt, in_rec))) {
        //Iterate over all output fields; if the field is present in input template, copy it to output record
        // If missing, set null
        void *ptr1 = NULL, *ptr2 = NULL;
        ur_field_id_t id;
        ur_iter_t iter = UR_ITER_BEGIN;
        while ((id = ur_iter_fields_tmplt(out_tmplt, &iter)) != UR_INVALID_FIELD) {
           if (!ur_is_dynamic(id)) { //static field
              if (ur_is_present(in_tmplt, id)) {
                 ptr1 = ur_get_ptr_by_id(in_tmplt, in_rec, id);
                 ptr2 = ur_get_ptr_by_id(out_tmplt, out_rec, id);
             //copy the data
                 if ((ptr1 != NULL) && (ptr2 != NULL)) {
                    memcpy(ptr2, ptr1, ur_get_size_by_id(id));
                 }
              } else { //missing static field
                 SET_NULL(id, out_tmplt, out_rec);
              }
           } else { //dynamic field
              if (ur_is_present(in_tmplt, id)) {
                 char* in_ptr = ur_get_dyn(in_tmplt, in_rec, id);
                 int size = ur_get_dyn_size(in_tmplt, in_rec, id);
                 char* out_ptr = ur_get_dyn(out_tmplt, out_rec, id);
                 // Check size of dynamic field and if longer than maximum size then cut it
                 if (size > DYN_FIELD_MAX_SIZE)
                    size = DYN_FIELD_MAX_SIZE;
                 //copy the data
                 memcpy(out_ptr, in_ptr, size);
                 //set offset to the end of the data in the new record
                 int new_offset = ur_get_dyn_offset_start(out_tmplt, out_rec, id) + size;
                 ur_set_dyn_offset(out_tmplt, out_rec, id, new_offset);
              } else { //missing dynamic field
                 ur_set_dyn_offset(out_tmplt, out_rec, id, ur_get_dyn_offset_start(out_tmplt, out_rec, id));
              }
           }
        }

        // Send record to interface 0
        ret = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));
        trap_send_flush(0);
        // Handle possible errors
        TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
     }

      // Quit if maximum number of records has been reached
      num_records++;
      if (max_num_records && max_num_records == num_records) {
         stop = 1;
      }

   }

   // ***** Cleanup *****
   TRAP_DEFAULT_FINALIZATION();

   freeAST(tree);

   if (unirec_output_specifier != NULL) {
      free(unirec_output_specifier);
      unirec_output_specifier = NULL;
   }
   if (from && unirec_output != NULL) {
      free(unirec_output);
      unirec_output = NULL;
   }
   ur_free(out_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);

   return 0;
}

