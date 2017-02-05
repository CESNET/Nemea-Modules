/**
 * \file unirecfilter.c
 * \brief NEMEA module selecting records and sending specified fields.
 * \author Klara Drhova <drhovkla@fit.cvut.cz>
 * \author Zdenek Kasner <kasnezde@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Miroslav Kalina <kalinmi2@fit.cvut.cz>
 * \date 2013
 * \date 2014
 * \date 2015
 * \date 2016
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "unirecfilter.h"
#include "fields.h"
#include <liburfilter.h>

UR_FIELDS ()
// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("unirecfilter",  "This NEMEA module selects records according to parameters in filter and sends "  \
   "only fields specified in output template. " \
   "Unirecfilter expects unirec format of messages on input. Output format is " \
   "specified with -O flag, filter is specified with -F flag and contains expressions (<=, ==, &&, ...). " \
   "You can also specify output format and filter in a FILE, which allows sending " \
   "output to multiple interfaces. \n" \
   ,1,-1)

#define MODULE_PARAMS(PARAM) \
  PARAM('O', "unirec_out", "Specify UniRec data format expected on the output interface. (UniRec data format example:\"uint32 FOO,string BAR\")", required_argument, "string") \
  PARAM('F', "filter", "Specify filter.", required_argument, "string") \
  PARAM('n', "no_eof", "Don't send 'EOF message' at the end.", no_argument, "none") \
  PARAM('f', "file", "Read template and filter from file.", required_argument, "string") \
  PARAM('c', "cut", "Quit after N records are received.", required_argument, "int32") \

static int stop = 0;               // Flag to interrupt process
static int send_eof = 1;           // Flag to enable EOF
int reload_filter = 0;             // Flag to reload filter from file
int verbose;                       // Verbosity level

unsigned int num_records = 0;      // Number of records received (total of all inputs)
unsigned int max_num_records = 0;  // Exit after this number of records is received
unsigned int max_num_ifaces = 32;  // Maximum number of output interfaces

char *str_buffer = NULL;           // Auxiliary buffer for evalAST()

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

// Handler for SIGUSR1 to set flag for force filter reloading
void reload_filter_signal_handler(int signum) {
   reload_filter = 1;
}

// Structure with information for each output interface
struct unirec_output_t {
   char *output_specifier_str;
   char *unirec_output_specifier;
   char *filter_str;
   urfilter_t *filter;
   ur_template_t *out_tmplt;
   void *out_rec;
};

// Search for delimiter (skip literals within string)
char *skip_str_chr(char *ptr, char delim)
{
   char c;
   int str_flag = 0;

   while ((c = *ptr) != delim || str_flag) {
      if (!(*++ptr)) {
         return NULL;
      }
      // Skip escaped character
      if (c == '\\') {
         ptr++;
      } else if (c == '"') {
      // Toggle string flag
         str_flag = !str_flag;
      }
   }
   return ptr;
}

// Set record default value if specified, otherwise set null value
void set_default_values(struct unirec_output_t *output_specifier) {
   char *ptr;
   char *token;
   char *f_names;

   f_names = ur_ifc_data_fmt_to_field_names(output_specifier->output_specifier_str);
   token = strtok(f_names, ",");

   while (token != NULL) {
      // Default value is set
      if ((ptr = strchr(token, '=')) != NULL) {
         *ptr = '\0';
         printf("%s set default to %s\n", token, ptr+1);

         // Trim quotes from string
         if (*(ptr+1) == '"') {
            ptr++;
            *(skip_str_chr(ptr+1, '"')) = '\0';
         }
         ur_set_from_string(output_specifier->out_tmplt, output_specifier->out_rec, ur_get_id_by_name(token), ptr+1);
      // Default value is not set
      } else {
         int id = ur_get_id_by_name(token);

         if (ur_is_dynamic(id)) {
            ur_set_var(output_specifier->out_tmplt, output_specifier->out_rec, id, NULL, 0);
         } else {
            SET_NULL(id, output_specifier->out_tmplt, output_specifier->out_rec);
         }
      }
      token = strtok(NULL, ",");
   }
   free(f_names);
}

// Create output specifier cleaned from default values assignments
int parse_output_specifier_from_str(struct unirec_output_t *output_specifier) {
   char *out_spec_ptr;
   char *ptr1, *ptr2;

   // Output specifier string to be created
   output_specifier->unirec_output_specifier = (char*) malloc(strlen(output_specifier->output_specifier_str)+1);
   out_spec_ptr = output_specifier->unirec_output_specifier;
   ptr1 = output_specifier->output_specifier_str;

   // Parse tokens
   while ((ptr2 = skip_str_chr(ptr1+1, ',')) != NULL) {
      // Look for default value assignment, copy only first part
      while (*ptr1 && *ptr1 != '=' && ptr1 < ptr2) {
         *out_spec_ptr++ = *ptr1++;
      }
      ptr1 = ptr2;
   } // Parse the last token
   while (*ptr1 && *ptr1 != '=') {
      *out_spec_ptr++ = *ptr1++;
   }
   *out_spec_ptr = 0;
   return 0;
}

// Parse file and fill structures with filters and specifiers, return number of succesfully loaded interfaces
int parse_file(char *str, struct unirec_output_t **output_specifiers, int n_outputs)
{
   int iface_index = 0; // Output interface index
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
         if ((end_ptr = skip_str_chr(end_ptr, ';')) == NULL) {
            fprintf(stderr, "Syntax error while parsing file: delimiter ';' not found.\n");
            return -1;
         }
         else if (end_ptr == beg_ptr) {
            // Empty filter
            output_specifiers[iface_index]->filter_str = NULL;
         }
         else {
            // Allocate and fill field for filter for this interface
            if ((output_specifiers[iface_index]->filter_str = (char *) calloc(end_ptr - beg_ptr + 1, 1)) == NULL) {
               fprintf(stderr, "Filter is too large, not enough memory.\n");
                  return -1;
            }
            memcpy(output_specifiers[iface_index]->filter_str, beg_ptr, end_ptr - beg_ptr);
            if (verbose >= 0) {
               printf("VERBOSE: Filter for interface %d as string: %s\n", iface_index, output_specifiers[iface_index]->filter_str);
            }
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
         if ((end_ptr = skip_str_chr(end_ptr, ':')) == NULL) {
            fprintf(stderr, "Syntax error while parsing filter file: delimiter ':' not found.\n");
            return -1;
         }
         // Allocate and fill field for output specification for this interface
         if ((output_specifiers[iface_index]->output_specifier_str = (char *) calloc(end_ptr - beg_ptr + 1, 1)) == NULL) {
            fprintf(stderr, "Filter is too large, not enough memory.\n");
            return -1;
         };
         memcpy(output_specifiers[iface_index]->output_specifier_str, beg_ptr, end_ptr - beg_ptr);
         if (verbose >= 0) {
            printf("VERBOSE: Output specifier for interface %d as string: %s\n", iface_index, output_specifiers[iface_index]->output_specifier_str);
         }
         break;
      }
   }
   return iface_index;
}

// Read file content to buffer, return pointer to buffer
char *load_file(char *filename)
{
   int f_size;   // Size of file with filter
   char *file_buffer = NULL;
   FILE *f = NULL;

   f = fopen(filename, "rt");
   // File cannot be opened / not found
   if (f == NULL) {
      fprintf(stderr, "Error: File %s could not be opened.\n", filename);
      return NULL;
   }
   // Determine the file size for memory allocation
   fseek(f, 0, SEEK_END);
   f_size = ftell(f);
   fseek(f, 0, SEEK_SET);

   // Allocate file buffer
   file_buffer = (char*) malloc (f_size + 1);

   if (fread(file_buffer, sizeof(char), f_size, f) != f_size) {
      fprintf(stderr, "Error: File %s could not be read.\n", filename);
      free(file_buffer);
      fclose(f);
      return NULL;
   }
   file_buffer[f_size] = '\0';
   fclose(f);

   return file_buffer;
}

// Load filter from file, handle errors
int get_filter_from_file(char * filename, struct unirec_output_t **output_specifiers, int n_outputs)
{
   int ret;
   char *file_buffer = NULL;

   // Copy file content into buffer
   if ((file_buffer = load_file(filename)) == NULL) {
      return 7;
   }
   // Fill structure(s) with output specifications
   if ((ret = parse_file(file_buffer, output_specifiers, n_outputs)) < 0) {
      free(file_buffer);
      return 7;
   };
   // Number of filters specified in file is not sufficient
   if (ret < n_outputs) {
      fprintf(stderr, "Error: number of output filters specified in file (%d) is lower than expected (%d).\n", ret, n_outputs);
      free(file_buffer);
      return 8;
   }
   free(file_buffer);
   return 0;
}

// Create templates based on data from filter
int create_templates(int n_outputs, char **port_numbers, struct unirec_output_t **output_specifiers) {
   int i;
   int memory_needed = 0;

   // Create trees and templates for all items
   for (i = 0; i < n_outputs; i++) {
      // Create UniRec output template and record
      if (output_specifiers[i]->output_specifier_str && output_specifiers[i]->output_specifier_str[0] != '\0') { // Not NULL or Empty
        parse_output_specifier_from_str(output_specifiers[i]);

        if (ur_define_set_of_fields(output_specifiers[i]->unirec_output_specifier) != UR_OK) {
            fprintf(stderr, "Error: output template format is not accurate.\n \
It should be: \"type1 name1,type2 name2,...\".\n \
Name of field may be any string matching the reqular expression [A-Za-z][A-Za-z0-9_]*\n\
Available types are: int8, int16, int32, int64, uint8, uint16, uint32, uint64, char,\
float, double, ipaddr, string, bytes\n");
            return -2;
         }
         char *f_names = ur_ifc_data_fmt_to_field_names(output_specifiers[i]->unirec_output_specifier);
         output_specifiers[i]->out_tmplt = ur_create_output_template(i, f_names, NULL);

         free(f_names);
         if (output_specifiers[i]->out_tmplt == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            return -1;
         }
      } else {
         fprintf(stderr, "ERROR: output data format is not set.\n");
      }

      // Get Abstract syntax tree from filter
      output_specifiers[i]->filter = urfilter_create(output_specifiers[i]->filter_str);

      // Calculate maximum needed memory for dynamic fields
      ur_field_id_t field_id = UR_ITER_BEGIN;
      while ((field_id = ur_iter_fields(output_specifiers[i]->out_tmplt, field_id)) != UR_ITER_END) {
         if (ur_is_dynamic(field_id)) {
            memory_needed += DYN_FIELD_MAX_SIZE;
         }
      }
      output_specifiers[i]->out_rec = ur_create_record(output_specifiers[i]->out_tmplt, memory_needed);
      set_default_values(output_specifiers[i]);
   }
   return 0;
}

int main(int argc, char **argv)
{
   struct unirec_output_t **output_specifiers = NULL; // filters and output specifiers
   char **port_numbers;
   char *output_specifier_str = NULL;
   char *filter = NULL;
   char *filename = NULL;
   ur_template_t *in_tmplt;
   const void *in_rec;
   uint16_t in_rec_size;
   char *req_format = NULL;
   signed char opt;
   int ret;
   int i;
   int from = 0; // 0 - template and filter from CMD, 1 - from file
   int n_outputs;
   trap_ifc_spec_t ifc_spec;

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // Register signal handler for reloading file with filter
   signal(SIGUSR1, reload_filter_signal_handler);

   // Parse TRAP parameters
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(module_info);
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   // Parse command-line options
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'O':
         // Using strdup is necessary for freeing correctly
         output_specifier_str = strdup(optarg);
         break;
      case 'F': // Filter
         filter = strdup(optarg);
         break;
      case 'n': // EOF message at the end of module's life
         send_eof = 0;
         break;
      case 'f': // File
         filename = optarg;
         from = 1;
         break;
      case 'c': {
         int nb = atoi(optarg);
         if (nb <= 0) {
            fprintf(stderr, "Error: Parameter of -c option must be > 0.\n");
            // Do all necessary cleanup before exiting
            TRAP_DEFAULT_FINALIZATION();
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 3;
         }
         max_num_records = nb;
         break;
      }
      default:
         fprintf(stderr, "Error: Invalid arguments.\n");
         // Do all necessary cleanup before exiting
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 4;
      }
   }

   verbose = trap_get_verbose_level();
   if (verbose >= 0) {
      printf("Verbosity level: %i\n", verbose);
   }

   // Count number of output interfaces
   n_outputs = strlen(ifc_spec.types) - 1;
   module_info->num_ifc_out = n_outputs;
   printf("Output interfaces: %d\n", n_outputs);

   // No output interfaces
   if (n_outputs < 1) {
      fprintf(stderr, "Error: You must specify at least one output interface.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }
   // More than one output interface specified from command line
   if (from == 0 && n_outputs > 1) {
      fprintf(stderr, "Error: For more than one output interface use parameter -f FILE.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }
   // Number of output interfaces exceeds TRAP limit
   if (n_outputs > 32) {
      fprintf(stderr, "Error: More than 32 interfaces is not allowed by TRAP library.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   // Filter and file are both set (-F and -f)
   else if ((filter != NULL) && (filename != NULL)) {
      fprintf(stderr, "Error: Invalid arguments - two filters.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 6;
   }

   // Save output interfaces numbers
   port_numbers = (char**) malloc(n_outputs * sizeof(char*));
   for (i = 1; i <= n_outputs; i++) {
      port_numbers[i-1] = strdup(ifc_spec.params[i]);
   }

   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      trap_free_ifc_spec(ifc_spec);
      for (i = 0; i < n_outputs; i++) {
          free(port_numbers[i]);
      }
      free(port_numbers);
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   // Create input template
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, "");
   ret = trap_recv(0, &in_rec, &in_rec_size);
   if (ret == TRAP_E_FORMAT_CHANGED) {
      const char *spec = NULL;
      uint8_t data_fmt;
      if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
         fprintf(stderr, "Data format was not loaded.");
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 5;
      }
      in_tmplt = ur_define_fields_and_update_template(spec, NULL);
      if (in_tmplt == NULL) {
         fprintf(stderr, "Template could not be edited");
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 5;
      }
      req_format = ur_cpy_string(spec);
      if (req_format == NULL) {
         fprintf(stderr, "Template could not be edited");
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 5;
      }
      trap_set_required_fmt(0, TRAP_FMT_UNIREC, req_format);
   } else {
      fprintf(stderr, "Data format was not received on input interface");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 5;
   }

   // Create array of structures with output interfaces specifications
   output_specifiers = (struct unirec_output_t**) calloc(sizeof(struct unirec_output_t*), n_outputs);

   // Allocate new structures with output interfaces specifications
   for (i = 0; i < n_outputs; i++) {
      output_specifiers[i] = (struct unirec_output_t*) calloc(sizeof(struct unirec_output_t), 1);
   }

   // From command line
   if (from == 0) {
      if (verbose >= 0) {
         printf("VERBOSE: Filter and output specifier loaded from command line\n");
      }
      output_specifiers[0]->output_specifier_str = output_specifier_str;
      output_specifiers[0]->filter_str = filter;
   } else {  // From file
      if (verbose >= 0) {
         printf("VERBOSE: Filter and output specifier will be loaded from file %s\n", filename);
      }
      if ((ret = get_filter_from_file(filename, output_specifiers, n_outputs)) != 0) {
         for (i = 0; i < n_outputs; i++) {
            free(port_numbers[i]);
         }
         free(port_numbers);
         trap_free_ifc_spec(ifc_spec);
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return ret;
      }
   }
   //if the output data format is null, use input data format
   for (i = 0; i < n_outputs; i++) {
      if (output_specifiers[i]->output_specifier_str == NULL) {
         output_specifiers[i]->output_specifier_str = ur_cpy_string(req_format);
      }
   }
   // Create templates from output specifiers
   if ((ret = create_templates(n_outputs, port_numbers, output_specifiers)) != 0) {
      for (i = 0; i < n_outputs; i++) {
         free(port_numbers[i]);
      }
      free(port_numbers);
      trap_free_ifc_spec(ifc_spec);
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return ret;
   }

   // Allocate auxiliary buffer for evalAST()
   str_buffer = (char *) malloc(65536 * sizeof(char)); // No string in unirec can be longer than 64kB
   if (str_buffer == NULL) {
      fprintf(stderr, "Error: Not enough memory for string buffer.\n");
      stop = 1;
   }

   // Free ifc_spec structure
   trap_free_ifc_spec(ifc_spec);

   if (verbose >= 0) {
         printf("VERBOSE: Main loop started\n");
   }
   // Main loop
   // Copy data from input to output
   while (!stop) {
      // Receive data from any input interface, wait until data are available
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break;   // End of data (used for testing purposes)
         } else {
            fprintf(stderr,
               "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
               ur_rec_fixlen_size(in_tmplt),
               in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA
      for (i = 0; i < n_outputs; i++) {
         if (!output_specifiers[i]->filter || urfilter_match(output_specifiers[i]->filter, in_tmplt, in_rec)) {
            if (verbose >= 1) {
               printf("ADVANCED VERBOSE: Record %ud accepted on interface %d\n", num_records, i);
            }
            //Iterate over all output fields; if the field is present in input template, copy it to output record
            // If missing, set null
            void *ptr1 = NULL, *ptr2 = NULL;
            ur_field_id_t id = 0;
            int rec_ind = 0;
            while ((id = ur_iter_fields_record_order(output_specifiers[i]->out_tmplt, rec_ind++)) != UR_ITER_END) {
               if (ur_is_present(in_tmplt, id)) {
                  if (!ur_is_dynamic(id)) { //static field
                     ptr1 = ur_get_ptr_by_id(in_tmplt, in_rec, id);
                     ptr2 = ur_get_ptr_by_id(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id);
                     //copy the data
                     if ((ptr1 != NULL) && (ptr2 != NULL)) {
                        memcpy(ptr2, ptr1, ur_get_size(id));
                     }
                  } else { //dynamic field
                     char *in_ptr = ur_get_ptr_by_id(in_tmplt, in_rec, id);
                     int size = ur_get_var_len(in_tmplt, in_rec, id);
                     // Check size of dynamic field and if longer than maximum size then cut it
                     if (size > DYN_FIELD_MAX_SIZE)
                        size = DYN_FIELD_MAX_SIZE;
                     //copy the data
                     ur_set_var(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec, id, in_ptr, size);
                  }
               }
            }
            // Send record to corresponding interface
            ret = trap_send(i, output_specifiers[i]->out_rec, ur_rec_size(output_specifiers[i]->out_tmplt, output_specifiers[i]->out_rec));
            trap_send_flush(i);
            // Handle possible errors
            TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, continue, {stop=1; break;});
         } else {
            if (verbose >= 1) {
                  printf("ADVANCED VERBOSE: Record %ud declined on interface %d\n", num_records, i);
            }
         }
      }
      // SIGUSR1 has been sent, reload filter
      if (reload_filter == 1) {
         printf("\nReloading filter...\n\n");
         printf("New filter:\n");

         if (get_filter_from_file(filename, output_specifiers, n_outputs) != 0
            || create_templates(n_outputs, port_numbers, output_specifiers) != 0) {
               stop = 1;
         }
         reload_filter = 0;
      }
      // Quit if maximum number of records has been reached
      num_records++;
      if (max_num_records && max_num_records == num_records) {
         stop = 1;
      }
   }

   // ***** Cleanup *****
   if (verbose >= 0) {
      printf("VERBOSE: Cleanup...\n");
   }
   free(str_buffer);

   if (send_eof == 1) {
      for (i = 0; i < n_outputs; i++) {
         ret = trap_send(i, output_specifiers[i]->out_rec, 1);
      }
   }

   TRAP_DEFAULT_FINALIZATION();
   ur_free_template(in_tmplt);
   free(req_format);

   for (i = 0; i < n_outputs; i++) {
      if (output_specifiers[i]->filter != NULL) {
         urfilter_destroy(output_specifiers[i]->filter);
         output_specifiers[i]->filter = NULL;
      }
      if (output_specifiers[i]->output_specifier_str != NULL) {
         free(output_specifiers[i]->output_specifier_str);
         output_specifiers[i]->output_specifier_str = NULL;
      }
      if (output_specifiers[i]->unirec_output_specifier != NULL) {
         free(output_specifiers[i]->unirec_output_specifier);
         output_specifiers[i]->unirec_output_specifier = NULL;
      }
      if (output_specifiers[i]->filter_str != NULL) {
         free(output_specifiers[i]->filter_str);
         output_specifiers[i]->filter_str = NULL;
      }
      ur_free_record(output_specifiers[i]->out_rec);
      ur_free_template(output_specifiers[i]->out_tmplt);
      free(output_specifiers[i]);
      free(port_numbers[i]);
   }
   free(port_numbers);
   free(output_specifiers);
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return 0;
}
