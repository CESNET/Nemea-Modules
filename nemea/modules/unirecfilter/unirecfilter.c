/**
 * \file unirecfilter.c
 * \brief NEMEA module selecting records and sending specified fields.
 * \author Klara Drhova <drhovkla@fit.cvut.cz>
 * \author Zdenek Kasner <kasnezde@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2013
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2013-2015 CESNET
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
#include <ctype.h>

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
   "You can also specify output format and filter in a FILE, which allows sending \n"
   "output to multiple interfaces.\n"
   "Format of the file is [TMPLT_1]:FILTER_1; ...; [TMPLT_N]:FILTER_N; where each\n"
   "filter corresponds with one output interface. One-line comments starting with\n"
   "'#' are allowed. When is -O flag missing, template from input is used on output.\n"
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
   "   Outputs: variable\n",
   1,       // Number of input interfaces
   -1,      // Number of output interfaces (-1 = variable)
};

static int stop = 0;

unsigned int num_records = 0; // Number of records received (total of all inputs)
unsigned int max_num_records = 0; // Exit after this number of records is received
unsigned int max_num_ifaces = 32; // Maximum number of output interfaces

char *str_buffer = NULL;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

// Structure with information for each output interface
struct unirec_output_t
{
   char *unirec_output_specifier;
   char *filter;
   struct ast *tree;
   ur_template_t *out_tmplt;
   void *out_rec;
};

// Parse file with filters and specifiers, fill structures with specified data
int parse_file(char *str, struct unirec_output_t **output_specifiers, int n_outputs)
{
   int iface_index = 0; // output interface index
   char *beg_ptr = str;
   char *end_ptr = str;

   while (iface_index < max_num_ifaces && iface_index < n_outputs)
   {
      switch (*end_ptr) {
      // End of file
      case '\0':
         return iface_index;
      // Comment
      case '#':
         if ((end_ptr = strchr(end_ptr, '\n')) == NULL) {
            return iface_index;
         }
         break;
      // Beginning of filter
      case ':':
         beg_ptr = end_ptr + 1;
         if ((end_ptr = strchr(end_ptr, ';')) == NULL) {
            fprintf(stderr, "Syntax error while parsing file: delimiter ';' not found.\n");
            return -1;
         }
         else if (end_ptr == beg_ptr) {
            // Empty filter
            output_specifiers[iface_index]->filter = NULL;
         }
         else {
            // Allocate and fill field for filter for this interface
            if ((output_specifiers[iface_index]->filter = (char *) malloc(end_ptr - beg_ptr)) == NULL) {
               fprintf(stderr, "Filter is too large, not enough memory.\n");
                  return -1;
            }
            memcpy(output_specifiers[iface_index]->filter, beg_ptr, end_ptr - beg_ptr);
         }
         iface_index++;
         break;
      // End of previous filter or whitespace
      case ';':
      case ' ':
      case '\t':
      case '\n':
         end_ptr++;
         break;
      // Beginning of output specifier
      default:
         beg_ptr = end_ptr;
         if ((end_ptr = strchr(end_ptr, ':')) == NULL) {
            fprintf(stderr, "Syntax error while parsing filter file: delimiter ':' not found.\n");
            return -1;
         }
         // Allocate and fill field for output specification for this interface
         if ((output_specifiers[iface_index]->unirec_output_specifier = (char *) malloc(end_ptr - beg_ptr)) == NULL) {
            fprintf(stderr, "Filter is too large, not enough memory.\n");
            return -1;
         };
         memcpy(output_specifiers[iface_index]->unirec_output_specifier, beg_ptr, end_ptr - beg_ptr);
         break;
      }
   }
}

char *load_file(char * file)
{
   int f_size;   // size of file with filter
   char *file_buffer = NULL;
   FILE *f = NULL;

   f = fopen(file, "rt");
   // File cannot be opened / not found
   if (f == NULL) {
      fprintf(stderr, "Error: File %s could not be opened.\n", file);
      return NULL;
   }

   // Determine the file size for memory allocation
   fseek(f, 0, SEEK_END);
   f_size = ftell(f);
   fseek(f, 0, SEEK_SET);

   file_buffer = (char *) malloc (f_size + 1);

   if (fread(file_buffer, sizeof(char), f_size, f) != f_size) {
      fprintf(stderr, "Error: File %s could not be read.\n", file);
      free(file_buffer);
      fclose(f);
      return NULL;
   }

   fclose(f);
   file_buffer[f_size] = '\0';

   return file_buffer;
}

int main(int argc, char **argv)
{
   struct unirec_output_t **output_specifiers = NULL; // filters and output specifiers
   char **port_numbers;
   char *unirec_output_specifier = NULL;
   char *unirec_input_specifier = NULL;
   char *filter = NULL;
   char *file = NULL;
   char *file_buffer = NULL;
   ur_template_t *in_tmplt;
   char opt;
   int ret;
   int i;
   int from = 0; // 0 - template and filter from CMD, 1 - from file
   int memory_needed = 0;
   int n_outputs;
   ur_field_id_t field_id = UR_INVALID_FIELD;

   trap_ifc_spec_t ifc_spec;
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }

   // Parse command-line options
   while ((opt = getopt(argc, argv, "I:O:F:f:c:")) != -1) {
      switch (opt) {
      case 'I':
         unirec_input_specifier = optarg;
         break;
      case 'O':
         // Using strdup is necessary for freeing correctly
         unirec_output_specifier = strdup(optarg);
         break;
      case 'F': // Filter
         filter = strdup(optarg);
         break;
      case 'f': // File
         file = optarg;
         from = 1;
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

   // Count number of output interfaces
   n_outputs = strlen(ifc_spec.types) - 1;
   module_info.num_ifc_out = n_outputs;
   printf("Output interfaces: %d\n", n_outputs);

   // No output interfaces
   if (n_outputs < 1) {
      fprintf(stderr, "Error: You must specify at least one UniRec template.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 1;
   }
   // More than one output interface specified from command line
   if (from == 0 && n_outputs > 1) {
      fprintf(stderr, "Error: For more than one output interface use parameter -f FILE.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 1;
   }
   // Number of output interfaces exceeds TRAP limit
   if (n_outputs > 32) {
      fprintf(stderr, "Error: More than 32 interfaces is not allowed by TRAP library.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 1;
   }
   // Input format specifier is missing
   if (unirec_input_specifier == NULL) {
      fprintf(stderr, "Error: Invalid arguments - no input specifier.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 5;
   }
   // Input format specifier is not valid
   else if ((in_tmplt = ur_create_template(unirec_input_specifier)) == NULL) {
      fprintf(stderr, "Error: Invalid arguments - input specifier is not valid.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 5;
   }

   // Output format specifier and file are both set (-O and -f)
   if ((unirec_output_specifier != NULL) && (file != NULL)) {
      fprintf(stderr, "Error: Invalid arguments - two output specifiers.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 6;
   }
   // Filter and file are both set (-F and -f)
   else if ((filter != NULL) && (file != NULL)) {
      fprintf(stderr, "Error: Invalid arguments - two filters.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 6;
   }

   // Save output interfaces numbers
   port_numbers = (char**) malloc(n_outputs * sizeof(char*));
   for (i = 1; i <= n_outputs; i++) {
      port_numbers[i-1] = strdup(ifc_spec.params[i]);
   }

   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      trap_free_ifc_spec(ifc_spec);
      for (i = 0; i < n_outputs; i++) {
          free(port_numbers[i]);
      }
      free(port_numbers);
      TRAP_DEFAULT_FINALIZATION();
      return 1;
   }

   // Create array of structures with output interfaces specifications
   output_specifiers = (struct unirec_output_t**) malloc(sizeof(struct unirec_output_t*) * n_outputs);

   // Allocate new structures with output interfaces specifications
   for (i = 0; i < n_outputs; i++) {
      output_specifiers[i] = (struct unirec_output_t*) malloc(sizeof(struct unirec_output_t));
   }

   if (from == 1) {
      // Copy file content into buffer
      if ((file_buffer = load_file(file)) == NULL) {
         for (i = 0; i < n_outputs; i++) {
            free(port_numbers[i]);
         }
         free(port_numbers);
         TRAP_DEFAULT_FINALIZATION();
         return 7;
      }
      // Fill structure(s) with output specifications
      if ((ret = parse_file(file_buffer, output_specifiers, n_outputs)) < 0) {
         for (i = 0; i < n_outputs; i++) {
            free(port_numbers[i]);
         }
         free(port_numbers);
         free(file_buffer);
         TRAP_DEFAULT_FINALIZATION();
         return 7;
      };
      // Number of filters specified in file is not sufficient
      if (ret < n_outputs) {
         fprintf(stderr, "Error: number of output filters specified in file is lower than expected (%d < %d).\n", ret, n_outputs);
         for (i = 0; i < n_outputs; i++) {
            free(port_numbers[i]);
         }
         free(port_numbers);
         TRAP_DEFAULT_FINALIZATION();
         return 8;
      }
      free(file_buffer);
   }

   else { // From command line
      output_specifiers[0]->unirec_output_specifier = unirec_output_specifier;
      output_specifiers[0]->filter = filter;
   }

   // Create trees and templates for all items
   for (i = 0; i < n_outputs; i++) {
      // Print output interface port number
      printf("[%s] ", port_numbers[i]);

      // Get Abstract syntax tree from filter
      output_specifiers[i]->tree = getTree(output_specifiers[i]->filter);

      // Create UniRec output template and record
      if (unirec_output_specifier && unirec_output_specifier[0] != '\0') { // Not NULL or Empty
         output_specifiers[i]->out_tmplt = ur_create_template(output_specifiers[i]->unirec_output_specifier);
      } else { //output template == input template
         output_specifiers[i]->out_tmplt = ur_create_template(unirec_input_specifier);
      }
      // Calculate maximum needed memory for dynamic fields
      while ((field_id = ur_iter_fields(output_specifiers[i]->out_tmplt, field_id)) != UR_INVALID_FIELD) {
         if (ur_is_dynamic(field_id)) {
            memory_needed += DYN_FIELD_MAX_SIZE;
         }
      }
      output_specifiers[i]->out_rec = ur_create(output_specifiers[i]->out_tmplt, memory_needed);
   }

   // Allocate auxiliary buffer for evalAST()
   str_buffer = (char *) malloc(65536 * sizeof(char)); // no string in unirec can be longer than 64kB
   if (str_buffer == NULL) {
      fprintf(stderr, "Error: Not enough memory for string buffer.\n");
      stop = 1;
   }

   // Free ifc_spec structure
   trap_free_ifc_spec(ifc_spec);

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
      for (i = 0; i < n_outputs; i++) {
         if (!(output_specifiers[i]->tree) || (output_specifiers[i]->tree && evalAST(output_specifiers[i]->tree, in_tmplt, in_rec))) {
           //Iterate over all output fields; if the field is present in input template, copy it to output record
           // If missing, set null
           void *ptr1 = NULL, *ptr2 = NULL;
           ur_field_id_t id;
           ur_iter_t iter = UR_ITER_BEGIN;
           while ((id = ur_iter_fields_tmplt(output_specifiers[i]->out_tmplt, &iter)) != UR_INVALID_FIELD) {
              if (!ur_is_dynamic(id)) { //static field
                 if (ur_is_present(in_tmplt, id)) {
                    ptr1 = ur_get_ptr_by_id(in_tmplt, in_rec, id);
                    ptr2 = ur_get_ptr_by_id(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id);
                //copy the data
                    if ((ptr1 != NULL) && (ptr2 != NULL)) {
                       memcpy(ptr2, ptr1, ur_get_size_by_id(id));
                    }
                 } else { //missing static field
                    SET_NULL(id, output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec);
                 }
              } else { //dynamic field
                 if (ur_is_present(in_tmplt, id)) {
                    char* in_ptr = ur_get_dyn(in_tmplt, in_rec, id);
                    int size = ur_get_dyn_size(in_tmplt, in_rec, id);
                    char* out_ptr = ur_get_dyn(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id);
                    // Check size of dynamic field and if longer than maximum size then cut it
                    if (size > DYN_FIELD_MAX_SIZE)
                       size = DYN_FIELD_MAX_SIZE;
                    //copy the data
                    memcpy(out_ptr, in_ptr, size);
                    //set offset to the end of the data in the new record
                    int new_offset = ur_get_dyn_offset_start(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id) + size;
                    ur_set_dyn_offset(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id, new_offset);
                 } else { //missing dynamic field
                    ur_set_dyn_offset(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id,
                                      ur_get_dyn_offset_start(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id));
                 }
              }
           }
           // Send record to corresponding interface
           ret = trap_send(i, output_specifiers[i]->out_rec, ur_rec_size(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec));
           trap_send_flush(i);
           // Handle possible errors
           TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
        }
     }

      // Quit if maximum number of records has been reached
      num_records++;
      if (max_num_records && max_num_records == num_records) {
         stop = 1;
      }
   }

   // ***** Cleanup *****
   free(str_buffer);
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(in_tmplt);

   for (i = 0; i < n_outputs; i++) {
      if (output_specifiers[i]->tree != NULL) {
         freeAST(output_specifiers[i]->tree);
         output_specifiers[i]->tree = NULL;
      }
      if (output_specifiers[i]->unirec_output_specifier != NULL) {
         free(output_specifiers[i]->unirec_output_specifier);
         output_specifiers[i]->unirec_output_specifier = NULL;
      }
      if (output_specifiers[i]->filter != NULL) {
         free(output_specifiers[i]->filter);
         output_specifiers[i]->filter = NULL;
      }
      ur_free(output_specifiers[i]->out_rec);
      ur_free_template(output_specifiers[i]->out_tmplt);
      free(output_specifiers[i]);
      free(port_numbers[i]);
   }
   free(port_numbers);
   free(output_specifiers);
   return 0;
}

