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
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <time.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <unirec/unirec2csv.h>
#include <ctype.h>
#include <inttypes.h>
#include "fields.h"

UR_FIELDS()

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("logger","This module logs all incoming UniRec records to standard output or into a specified file. Each record is written as one line containing values of its fields in human-readable format separated by chosen delimiters (CSV format).",1,0)

#define MODULE_PARAMS(PARAM) \
  PARAM('w', "write", "Write output to FILE instead of stdout (rewrite the file).", required_argument, "string") \
  PARAM('a', "append", "Write output to FILE instead of stdout (append to the end).", required_argument, "string") \
  PARAM('o', "output_fields", "(currently unavailable)Set of fields included in the output (UniRec data format example:\"uint32 FOO,time BAR\")", required_argument, "string") \
  PARAM('t', "title", "Write names of fields on the first line.", no_argument, "none") \
  PARAM('T', "time", "Add the time when the record was received as the first field.", no_argument, "none") \
  PARAM('c', "cut", "Quit after N records are received, 0 can be useful in combination with -t to print UniRec.", required_argument, "uint32") \
  PARAM('d', "delimiter", "Optionally modifies delimiter to inserted value X (implicitly ','). Delimiter has to be one character, except for printable escape sequences.", required_argument, "string")

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
static ur_template_t *in_template = NULL; // UniRec templates of input interfaces (array of length n_inputs)
static ur_template_t *out_template = NULL; // UniRec template with union of fields of all inputs
int print_time = 0;
int print_title = 0;
uint8_t out_template_defined = 0;
char delimiter = ',';

unsigned int num_records = 0; // Number of records received (total of all inputs)
unsigned int max_num_records = 0; // Exit after this number of records is received
char enabled_max_num_records = 0; // Limit of message is set when non-zero

static FILE *file; // Output file


// Signal handler registered through TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER()
void trap_default_signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   }
}


void capture_data()
{
   int fail = 0, ret;
   uint8_t data_fmt = TRAP_FMT_UNKNOWN;
   urcsv_t *csv = NULL;
   char *str_out = NULL;

   if (verbose >= 1) {
      printf("Capturing started.\n");
   }

   // Read data from input and log them to a file
   while (!stop) {
      const void *rec;
      uint16_t rec_size;

      if (verbose >= 2) {
         printf("Calling trap_recv()\n");
      }

      // Receive data from input interface 0, wait until data are available
      ret = trap_recv(0, &rec, &rec_size);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         const char *spec = NULL;
         if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Error: Data format was not loaded.\n");
            break;
         } else {
            in_template = ur_define_fields_and_update_template(spec, in_template);
            if (in_template == NULL) {
               fprintf(stderr, "Error: Template could not be created.\n");
               break;
            }

            if (out_template_defined == 0) {
               out_template = ur_define_fields_and_update_template(spec, out_template);
               if (out_template == NULL) {
                 fprintf(stderr, "Error: Output interface template couldn't be created.\n");
                 fflush(stderr);
                 fail = 1;
               } else {
                  out_template_defined = 1;
               }
            }

			 if (fail == 1) {
				 break;
			 }

            csv = urcsv_init(in_template, delimiter);

            if (print_title == 1 && out_template_defined == 1) {
               print_title = 0;
               // Print header - names of output UniRec fields
               if (print_time) {
                  fprintf(file, "time,");
               }
               str_out = urcsv_header(csv);
               if (str_out == NULL) {
                  fprintf(stderr, "Memory allocation error\n");
                  fail = 1;
               } else {
                  fprintf(file, "%s\n", str_out);
                  free(str_out);
                  fflush(file);
               }
            }

            if (fail == 1) {
               break;
            }
			 if ((enabled_max_num_records != 0) && (max_num_records == 0))
			 {
				break;
			 }
         }
      } else {
        TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      } // end if (ret == TRAP_E_FORMAT_CHANGED)

      if (verbose >= 1) {
         printf("Received %hu bytes of data\n", rec_size);
      }

      // Check size of received data
      if (rec_size < ur_rec_fixlen_size(in_template)) {
         if (rec_size <= 1) {
            if (verbose >= 0) {
               printf("Received ending record, interface will be closed.\n");
            }
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_template), rec_size);
            break;
         }
      }

      // Print contents of received UniRec to output
      if (print_time) {
         char str[32];
         time_t ts = time(NULL);
         strftime(str, 31, "%FT%T", gmtime(&ts));
         fprintf(file, "%s,", str);
      }

      str_out = urcsv_record(csv, rec);
      fprintf(file,"%s\n", str_out);
      free(str_out);
      fflush(file);

      num_records++;

      // Check whether maximum number of records has been reached
      if (enabled_max_num_records && num_records >= max_num_records) {
         stop = 1;
         trap_terminate();
         break;
      }
   } // end while (!stop)

   urcsv_free(&csv);

   if (verbose >= 1) {
      printf("Finished capturing.\n");
   }

}


int main(int argc, char **argv)
{
   int ret;
   char *out_template_str = NULL;
   char *out_filename = NULL;
   int append = 0;
   out_template_defined = 0;


   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

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
   long int long_int_opt = 0;
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
      	 fprintf(stderr, "Warning: parameter -o is currently not supported and will be ignored.\n");
         out_template_str = optarg;
         break;
      case 't':
         print_title = 1;
         break;
      case 'T':
         print_time = 1;
         break;
      case 'c':

         long_int_opt = strtol(optarg, NULL, 10);
         if (max_num_records < 0) {
         	fprintf(stderr, "Error: Negative -c parameter. (max. records captured)");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 1;
         } else if (long_int_opt > UINT_MAX) {
            fprintf(stderr, "Error: -c parameter is too large. (max. records captured)");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 1;
         } else {
            max_num_records = (unsigned int) long_int_opt;
         }
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

   // Create UniRec templates
   if (verbose >= 0) {
      printf("Creating UniRec templates ...\n");
   }

   //initialize template for negotiation
   in_template = ur_create_input_template(0, NULL, NULL);
   if (in_template == NULL) {
      fprintf(stderr, "Memory allocation error.\n");
	   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

	   ret = -1;
      goto exit;
   }
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, NULL);

   // Create output UniRec template (user-specified or union of all inputs)
   if (out_template_str != NULL) {
      if (ur_define_set_of_fields(out_template_str) != UR_OK) {
         fprintf(stderr, "Error: output template format is not accurate.\n"
                         "It should be: \"type1 name1,type2 name2,...\".\n"
                         "Name of field may be any string matching the reqular expression [A-Za-z][A-Za-z0-9_]*\n"
                         "Available types are: int8, int16, int32, int64, uint8, uint16, uint32, uint64, char,"
                         "float, double, ipaddr, macaddr, time, string, bytes\n");
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

   // ***** Process data *****
	capture_data();

   ret = 0;

   // ***** Cleanup *****

exit:
   if (verbose >= 0) {
      printf("Exitting ...\n");
   }

   trap_terminate(); // This have to be called before trap_finalize(), otherwise it may crash (don't know if feature or bug in TRAP)

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(in_template);
   ur_free_template(out_template);
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return ret;
}

