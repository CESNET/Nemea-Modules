/**
 * \file logger.c
 * \brief Logs incoming UniRec records into file(s).
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \author Katerina Pilatova <xpilat05@stud.fit.vutbr.cz>
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

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <pthread.h>
#include <ctype.h>
#include "fields.h"

UR_FIELDS()

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("logger","This module logs all incoming UniRec records to standard output or into a specified file. Each record is written as one line containing values of its fields in human-readable format separated by chosen delimiters (CSV format). If you use more than one input interface you have to specify output format by parameter \"-o\".",-1,0)

#define MODULE_PARAMS(PARAM) \
  PARAM('w', "write", "Write output to FILE instead of stdout (rewrite the file).", required_argument, "string") \
  PARAM('a', "append", "Write output to FILE instead of stdout (append to the end).", required_argument, "string") \
  PARAM('o', "output_fields", "Set of fields included in the output (UniRec data format example:\"uint32 FOO,time BAR\")", required_argument, "string") \
  PARAM('t', "title", "Write names of fields on the first line.", no_argument, "none") \
  PARAM('T', "time", "Add the time when the record was received as the first field.", no_argument, "none") \
  PARAM('n', "ifc_num", "Add the number of interface the record was received on as the first field (or second when -T is specified).", no_argument, "none") \
  PARAM('N', "interface_count", "Number of input interfaces. Default: 1 interface", required_argument, "uint32") \
  PARAM('c', "cut", "Quit after N records are received, 0 can be useful in combination with -t to print UniRec.", required_argument, "uint32") \
  PARAM('d', "delimiter", "Optionally modifies delimiter to inserted value X (implicitely ','). Delimiter has to be one character, except for printable escape sequences.", required_argument, "string")

/* If delimiter is escape sequence, assigns its value from input to delimiter var. */
#define ESCAPE_SEQ(arg,err_cmd) do { \
           switch(arg) {\
              case 'f': delimiter = '\f';\
                        break;\
              case 'n': delimiter = '\n';\
                        break;\
              case 'r': delimiter = '\r';\
                        break;\
              case 't': delimiter = '\t';\
                        break;\
              case 'v': delimiter = '\v';\
                        break;\
              default:\
                 fprintf(stderr, "Error: Parameter of -d option is not a printable"\
                                 " escape sequence [\\f \\n \\r \\t \\v].\n");\
                 err_cmd;\
           }\
        } while (0)


static int stop = 0;

int verbose;
static int n_inputs = 1; // Number of input interfaces
static ur_template_t **templates = NULL; // UniRec templates of input interfaces (array of length n_inputs)
static ur_template_t *out_template = NULL; // UniRec template with union of fields of all inputs
int print_ifc_num = 0;
int print_time = 0;
int print_title = 0;
uint8_t out_template_defined = 0;
char delimiter = ',';

unsigned int num_records = 0; // Number of records received (total of all inputs)
unsigned int max_num_records = 0; // Exit after this number of records is received
char enabled_max_num_records = 0; // Limit of message is set when non-zero

pthread_mutex_t mtx;

static FILE *file; // Output file

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

void *capture_thread(void *arg)
{
   int index =  *(int *) arg, fail = 0, ret;
   uint8_t data_fmt = TRAP_FMT_UNKNOWN;

   if (verbose >= 1) {
      printf("Thread %i started.\n", index);
   }

   // Read data from input and log them to a file
   while (!stop) {
      const void *rec;
      uint16_t rec_size;

      if (verbose >= 2) {
         printf("Thread %i: calling trap_recv()\n", index);
      }

      // Receive data from index-th input interface, wait until data are available
      ret = trap_recv(index, &rec, &rec_size);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         const char *spec = NULL;
         if (trap_get_data_fmt(TRAPIFC_INPUT, index, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Error: Data format was not loaded.\n");
            break;
         } else {
            templates[index] = ur_define_fields_and_update_template(spec, templates[index]);
            if (templates[index] == NULL) {
               fprintf(stderr, "Error: Template could not be created.\n");
               break;
            }
            pthread_mutex_lock(&mtx);
            if (out_template_defined == 0) { // Check whether it is first thread trying to define output ifc template
               out_template = ur_define_fields_and_update_template(spec, out_template);
               if (out_template == NULL) {
                 fprintf(stderr, "Error: Output interface template couldn't be created.\n");
                 fflush(stderr);
                 fail = 1;
               } else {
                  out_template_defined = 1;
               }
            }

            if (print_title == 1 && out_template_defined == 1) {
               print_title = 0;
               // Print a header - names of output UniRec fields
               if (print_time) {
                  fprintf(file, "time,");
               }
               if (print_ifc_num) {
                  fprintf(file, "ifc,");
               }
               char *data_format = ur_template_string_delimiter(out_template, delimiter);
               if (data_format == NULL) {
                  fprintf(stderr, "Memory allocation error\n");
                  fail = 1;
               } else {
                  fprintf(file, "%s\n", data_format);
                  free(data_format);
                  fflush(file);
               }
            }
            pthread_mutex_unlock(&mtx);

            if (fail == 1) {
               break;
            }
         }
      } else {
        TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      }

      if (verbose >= 2) {
         printf("Thread %i: received %hu bytes of data\n", index, rec_size);
      }

      // Check size of received data
      if (rec_size < ur_rec_fixlen_size(templates[index])) {
         if (rec_size <= 1) {
            if (verbose >= 0) {
               printf("Interface %i received ending record, the interface will be closed.\n", index);
            }
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(templates[index]), rec_size);
            break;
         }
      }

      // Print contents of received UniRec to output
      pthread_mutex_lock(&mtx);
      if (print_time) {
         char str[32];
         time_t ts = time(NULL);
         strftime(str, 31, "%FT%T", gmtime(&ts));
         fprintf(file, "%s,", str);
      }
      if (print_ifc_num) {
         fprintf(file,"%i,", index);
      }
      // Iterate over all output fields
      int delim = 0;
      int i = 0;
      ur_field_id_t id = 0;
      while ((id = ur_iter_fields_record_order(out_template, i++)) != UR_ITER_END) {
         if (delim != 0) {
            fprintf(file,"%c", delimiter);
         }
         delim = 1;
         if (ur_is_present(templates[index], id)) {
            // Get pointer to the field (valid for static fields only)
            void *ptr = ur_get_ptr_by_id(templates[index], rec, id);
               // Static field - check what type is it and use appropriate format
            switch (ur_get_type(id)) {
               case UR_TYPE_UINT8:
                  fprintf(file, "%u", *(uint8_t*)ptr);
                  break;
               case UR_TYPE_UINT16:
                  fprintf(file, "%u", *(uint16_t*)ptr);
                  break;
               case UR_TYPE_UINT32:
                  fprintf(file, "%u", *(uint32_t*)ptr);
                  break;
               case UR_TYPE_UINT64:
                  fprintf(file, "%lu", *(uint64_t*)ptr);
                  break;
               case UR_TYPE_INT8:
                  fprintf(file, "%i", *(int8_t*)ptr);
                  break;
               case UR_TYPE_INT16:
                  fprintf(file, "%i", *(int16_t*)ptr);
                  break;
               case UR_TYPE_INT32:
                  fprintf(file, "%i", *(int32_t*)ptr);
                  break;
               case UR_TYPE_INT64:
                  fprintf(file, "%li", *(int64_t*)ptr);
                  break;
               case UR_TYPE_CHAR:
                  fprintf(file, "%c", *(char*)ptr);
                  break;
               case UR_TYPE_FLOAT:
                  fprintf(file, "%f", *(float*)ptr);
                  break;
               case UR_TYPE_DOUBLE:
                  fprintf(file, "%f", *(double*)ptr);
                  break;
               case UR_TYPE_IP:
                  {
                     // IP address - convert to human-readable format and print
                     char str[46];
                     ip_to_str((ip_addr_t*)ptr, str);
                     fprintf(file, "%s", str);
                  }
                  break;
               case UR_TYPE_TIME:
                  {
                     // Timestamp - convert to human-readable format and print
                     time_t sec = ur_time_get_sec(*(ur_time_t*)ptr);
                     int msec = ur_time_get_msec(*(ur_time_t*)ptr);
                     char str[32];
                     strftime(str, 31, "%FT%T", gmtime(&sec));
                     fprintf(file, "%s.%03i", str, msec);
                  }
                  break;
               case UR_TYPE_STRING:
                  {
                     // Printable string - print it as it is
                     int size = ur_get_var_len(templates[index], rec, id);
                     char *data = ur_get_ptr_by_id(templates[index], rec, id);
                     putc('"', file);
                     while (size--) {
                        switch (*data) {
                           case '\n': // Replace newline with space
                                      putc(' ', file);
                                      break;
                           case '"' : // Double quotes in string
                                      putc('"', file);
                                      putc('"', file);
                                      break;
                           default  : // Check if character is printable
                                      if (isprint(*data)) {
                                         putc(*data, file);
                                      }
                        }
                        data++;
                     }
                     putc('"', file);
                  }
                  break;
               case UR_TYPE_BYTES:
                  {
                     // Generic string of bytes - print each byte as two hex digits
                     int size = ur_get_var_len(templates[index], rec, id);
                     unsigned char *data = ur_get_ptr_by_id(templates[index], rec, id);
                     while (size--) {
                        fprintf(file, "%02x", *data++);
                     }
                  }
                  break;
               default:
                  {
                     // Unknown type - print the value in hex
                     int size = ur_get_len(templates[index], rec, id);
                     fprintf(file, "0x");
                     for (int i = 0; i < size; i++) {
                        fprintf(file, "%02x", ((unsigned char*)ptr)[i]);
                     }
                  }
                  break;
            } // case (field type)
         } // if present
      } // loop over fields
      fprintf(file,"\n");
      fflush(file);

      num_records++;
      pthread_mutex_unlock(&mtx);

      // Check whether maximum number of records has been reached
      if (max_num_records && num_records >= max_num_records) {
         stop = 1;
         trap_terminate();
         break;
      }
   } // end while (!stop)

   if (verbose >= 1) {
      printf("Thread %i exitting.\n", index);
   }

   return NULL;
}


int main(int argc, char **argv)
{
   int ret;
   char *out_template_str = NULL;
   char *out_filename = NULL;
   int append = 0;
   out_template_defined = 0;

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   // ***** Process parameters *****

   // Let TRAP library parse command-line arguments and extract its parameters
   trap_ifc_spec_t ifc_spec;
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }

   verbose = trap_get_verbose_level();
   if (verbose >= 0) {
      printf("Verbosity level: %i\n", trap_get_verbose_level());
   }

   // Parse remaining parameters and get configuration
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'a':
         append = 1;
         // continue below...
      case 'w':
         if (out_filename != NULL) { // Output file is already specified
            fprintf(stderr, "Error: Only one output file may be specified.\n");
            return 1;
         }
         out_filename = optarg;
         break;
      case 'o':
         out_template_str = optarg;
         break;
      case 't':
         print_title = 1;
         break;
      case 'n':
         print_ifc_num = 1;
         break;
      case 'N':
         n_inputs = atoi(optarg);
         break;
      case 'T':
         print_time = 1;
         break;
      case 'c':
         max_num_records = atoi(optarg);
         enabled_max_num_records = 1;
         break;
      case 'd':
         if ((strlen(optarg) == 1) && (sscanf(optarg, "%c", &delimiter) == 1)) {
            break;
         } else if ((strlen(optarg) == 2) && (optarg[0] == '\\')) {
            ESCAPE_SEQ(optarg[1], return 1);
            break;
         }

         fprintf(stderr, "Error: Parameter of -d option must contain 1 character"
                            " or escape sequence.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 1;
      default:
         fprintf(stderr, "Error: Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 1;
      }
   }

   // ***** TRAP initialization *****

   // Create UniRec templates
   if (verbose >= 0) {
      printf("Number of inputs: %i\n", n_inputs);
   }
   if (n_inputs < 1) {
      fprintf(stderr, "Error: Number of input interfaces must be positive integer.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 0;
   }
   if (n_inputs > 32) {
      fprintf(stderr, "Error: More than 32 interfaces is not allowed by TRAP library.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 4;
   }
   if (out_template_str == NULL && n_inputs > 1) {
      fprintf(stderr, "Error: If you use more than one interface, output template has to be specified.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 4;
   }

   // Set number of input interfaces
   module_info->num_ifc_in = n_inputs;

   if (verbose >= 0) {
      printf("Initializing TRAP library ...\n");
   }

   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      trap_free_ifc_spec(ifc_spec);
      ret = 2;
      goto exit;
   }

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   if (verbose >= 0) {
      printf("Creating UniRec templates ...\n");
   }
   templates = (ur_template_t**)calloc(n_inputs, sizeof(*templates));
   if (templates == NULL) {
      fprintf(stderr, "Memory allocation error.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return -1;
   }
   //initialize templates for negotiation
   for (int i = 0; i < n_inputs; i++) {
      templates[i] = ur_create_input_template(i, NULL, NULL);
      if (templates[i] == NULL) {
         fprintf(stderr, "Memory allocation error.\n");
         ret = -1;
         goto exit;
      }
      trap_set_required_fmt(i, TRAP_FMT_UNIREC, NULL);
   }

   // Create output UniRec template (user-specified or union of all inputs)
   if (out_template_str != NULL) {
      if (ur_define_set_of_fields(out_template_str) != UR_OK) {
         fprintf(stderr, "Error: output template format is not accurate.\n \
It should be: \"type1 name1,type2 name2,...\".\n \
Name of field may be any string matching the reqular expression [A-Za-z][A-Za-z0-9_]*\n\
Available types are: int8, int16, int32, int64, uint8, uint16, uint32, uint64, char,\
 float, double, ipaddr, time, string, bytes\n");
         ret = 2;
         goto exit;
      }
      char *f_names = ur_ifc_data_fmt_to_field_names(out_template_str);
      out_template = ur_create_template(f_names, NULL);
      free(f_names);
      if (out_template == NULL) {
         fprintf(stderr, "Memory allocation error\n");
         ret = -1;
         goto exit;
      }
      out_template_defined = 1;
   }

   // ***** Open output file *****

   // Open output file if specified
   if (out_filename != NULL) {
      if (verbose >= 0) {
         printf("Creating output file \"%s\" ...\n", out_filename);
      }
      if (append) {
         file = fopen(out_filename, "a");
      } else {
         file = fopen(out_filename, "w");
      }
      if (file == NULL) {
         perror("Error: can't open output file:");
         ret = 3;
         goto exit;
      }
   } else {
      file = stdout;
   }

   if (verbose >= 0) {
      printf("Initialization done.\n");
   }

   if ((enabled_max_num_records != 0) && (max_num_records == 0)) {
      // stop after printed title
      goto exit;
   }

   // ***** Start a thread for each interface *****

   int *interfaces = (int *) malloc(n_inputs * sizeof(int));
   pthread_t *threads = (pthread_t *) malloc(n_inputs * sizeof(pthread_t));
   pthread_attr_t attr;
   pthread_attr_init(&attr);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
   pthread_mutex_init(&mtx, NULL);

   for (int i = 0; i < n_inputs; i++) {
      interfaces[i] = i;
      if (pthread_create(&threads[i], &attr, capture_thread, &interfaces[i]) != 0) {
         fprintf(stderr, "pthread_create() failed\n");
         pthread_attr_destroy(&attr);
         pthread_mutex_destroy(&mtx);
         free(threads);
         free(interfaces);
         goto exit;
      }
   }
   pthread_attr_destroy(&attr);

   for (int i = 0; i < n_inputs; i++) {
      pthread_join(threads[i], NULL);
   }
   pthread_mutex_destroy(&mtx);
   free(threads);
   free(interfaces);

   ret = 0;

   // ***** Cleanup *****

exit:
   if (verbose >= 0) {
      printf("Exitting ...\n");
   }

   trap_terminate(); // This have to be called before trap_finalize(), otherwise it may crash (don't know if feature or bug in TRAP)

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   if (templates) {
      for (int i = 0; i < n_inputs; i++) {
         ur_free_template(templates[i]);
      }
   free(templates);
   }

   ur_free_template(out_template);
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return ret;
}

