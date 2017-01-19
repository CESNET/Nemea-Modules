/**
 * \file merger.c
 * \brief Merge traffic incoming on mutiple interfaces into one output stream.
 * \author Pavel Krobot <xkrobo01@cesnet.cz>
 * \date 3/2014
 */
/*
 * Copyright (C) 2014 CESNET
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
#include <unistd.h>
#include <omp.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

#define TS_LAST   0
#define TS_FIRST  1

#define INACTIVE_USLEEP_TIME  100000
#define DEFAULT_TIMEOUT       1000000
//#define DEFAULT_TIMEOUT     TRAP_WAIT
#define TIME_DIFF_SLEEP    5

#define MODE_TIME_IGNORE   0
#define MODE_TIME_AWARE    1

UR_FIELDS (
   time TIME_FIRST,
   time TIME_LAST
)

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("merger","This module merges traffic from multiple input interfaces to one output stream (on one interface).",-1,1)

#define MODULE_PARAMS(PARAM) \
  PARAM('F', "time_first", "(timestamp aware version) Sorts timestamps based on TIME_FIRST field, instead of TIME_LAST (default).", no_argument, "none") \
  PARAM('n', "link_count", "Sets count of input links. Must correspond to parameter -i (trap).", required_argument, "int32") \
  PARAM('u', "unirec", "UniRec specifier of input/output data (same to all links). (default <COLLECTOR_FLOW>).", required_argument, "string") \
  PARAM('t', "timeout", "(timestamp aware version) Set initial timeout for incoming interfaces (in seconds). Timeout is set to 0, if no data received in initial timeout (default 1s).", required_argument, "int32") \
  PARAM('T', "timestamp", "Set mode to timestamp aware (not by default).", no_argument, "none")

static int stop = 0;
static int verbose;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

static int timestamp_selector = TS_LAST; // Tells to sort timestamps based on TIME_FIRST or TIME_LAST field
static ur_time_t actual_min_timestamp = 0; // Actual minimal timestamp

static ur_template_t **in_template; // UniRec template of input interface(s)
static ur_template_t *out_template; // UniRec template of output interface

static int active_interfaces;
static int initial_timeout = DEFAULT_TIMEOUT; // Initial timeout for incoming interfaces (in miliseconds)

/**
 * Timestamp-aware capture thread - handles data incomming from on one interface.
 *
 * @param [in] index Index of the given link.
 */
void ta_capture_thread(int index)
{
   int private_stop = 0;
   int ret;

   int outage_flag = 0;
   int read_next = 1;
   int timeout = initial_timeout;
   ur_time_t rec_time;
   const void *rec;
   uint16_t rec_size;

   if (verbose >= 1) {
      printf("Thread %i started.\n", index);
   }

   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, timeout);


   ret = trap_recv(index, &rec, &rec_size);
   if (ret == TRAP_E_FORMAT_CHANGED) {
      const char *spec = NULL;
      uint8_t data_fmt;
      if (trap_get_data_fmt(TRAPIFC_INPUT, index, &data_fmt, &spec) != TRAP_E_OK) {
         fprintf(stderr, "Data format was not loaded.");
         return;
      } else {
         int fail = 0;
         #pragma omp critical
         {
            in_template[index] = ur_define_fields_and_update_template(spec, in_template[index]);
            if (in_template[index] == NULL) {
               fprintf(stderr, "Template could not be edited");
               fail = 1;
            } else {
               ur_expand_template(spec, out_template);
               char * spec_cpy = ur_template_string(out_template);
               if (spec_cpy == NULL) {
                  fprintf(stderr, "Memory allocation problem.");
                  fail = 1;

               } else {
                  trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec_cpy);
               }
            }
         }
         if (fail == 1) {
            return;
         }
      }
   } else {
      printf("ERROR on ifc %d: Negotiation was not succesfull\n", index);
      return;
   }

   void *data_out = ur_create_record(out_template, UR_MAX_SIZE);
   if (data_out == NULL) {
      fprintf(stderr, "ERROR: Allocation of record\n");
      return;
   }

   // Read data from input and log them to a file
   while (!stop && !private_stop) {
      if (stop) private_stop = stop;

      if (read_next){
         rec_time = 0;

         if (verbose >= 2) {
            printf("Thread %i: calling trap_recv()\n", index);
         }
         // Receive data from index-th input interface, wait until data are available

         ret = trap_recv(index, &rec, &rec_size);
         //update output template
         if (ret == TRAP_E_FORMAT_CHANGED) {
            const char *spec = NULL;
            uint8_t data_fmt;
            if (trap_get_data_fmt(TRAPIFC_INPUT, index, &data_fmt, &spec) != TRAP_E_OK) {
               fprintf(stderr, "Data format was not loaded.");
               return;
            } else {
               int fail = 0;
               #pragma omp critical
               {
                  in_template[index] = ur_define_fields_and_update_template(spec, in_template[index]);
                  if (in_template[index] == NULL) {
                     fprintf(stderr, "Template could not be edited");
                     fail = 1;
                  } else {
                     ur_expand_template(spec, out_template);
                     char * spec_cpy = ur_template_string(out_template);
                     if (spec_cpy == NULL) {
                        fprintf(stderr, "Memory allocation problem.");
                        fail = 1;
                     }
                     trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec_cpy);
                  }
               }
               if (fail == 1) {
                  break;
               }
               ret = trap_recv(index, &rec, &rec_size);
               memset(data_out, 0, UR_MAX_SIZE);
            }
         }

         if (ret != TRAP_E_OK) {
            if (ret == TRAP_E_TIMEOUT) {//input probably (temporary) offline
               if (verbose >= 0) {
                  printf("Thread %i: no data received (timeout %u).\n", index, timeout);
               }
            } else if (ret == TRAP_E_TERMINATED) {// Module was terminated while waiting for new data (e.g. by Ctrl-C)
               private_stop = 1;
            } else {
               // Some error has occured
               if (verbose >= 0) {
                  fprintf(stderr, "Error: trap_get_data() returned %i (%s)\n", ret, trap_last_error_msg);
               }
            }
            if(!outage_flag){
               outage_flag = 1;
               trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
               #pragma omp atomic
               --active_interfaces;
            }
         } else {
            if (verbose >= 2) {
               printf("Thread %i: received %hu bytes of data\n", index, rec_size);
            }
            // Check size of received data
            if (rec_size < ur_rec_fixlen_size(in_template[index])) {
               if (rec_size <= 1) {
                  if (verbose >= 0) {
                     printf("Interface %i received ending record, the interface will be closed.\n", index);
                  }
//                read_next = 0;
               } else {
                  if (verbose >= 0) {
                     fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                          ur_rec_fixlen_size(in_template[index]), rec_size);
                  }
               }
               if(!outage_flag){
                  outage_flag = 1;
                  trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
                  #pragma omp atomic
                  --active_interfaces;
               }
            } else {
               if (outage_flag) {
                  outage_flag = 0;
                  trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, timeout);
                  #pragma omp atomic
                  ++active_interfaces;
               }
               if (timestamp_selector == TS_FIRST){
                  rec_time = ur_get(in_template[index], rec, F_TIME_FIRST);
               } else {
                  rec_time = ur_get(in_template[index], rec, F_TIME_LAST);
               }
               read_next = 0;
            }
         }
      }

      #pragma omp barrier

      if (!outage_flag){
         #pragma omp critical (minimum)
         {
            if (actual_min_timestamp == 0 || actual_min_timestamp > rec_time){
               actual_min_timestamp = rec_time;
            } else {
      //       sleep(rec_time - actual_min_timestamp);
            }
         }
      }

      #pragma omp barrier

      if (!outage_flag){
         if (actual_min_timestamp == rec_time){
            ur_copy_fields(out_template, data_out, in_template[index], rec);
            #pragma omp critical (sending)
            {
               ret = trap_send(0, data_out, ur_rec_size(out_template, data_out));

               if (ret != TRAP_E_OK) {
                  if (ret == TRAP_E_TERMINATED) {
                     private_stop = 1; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
                     #pragma omp atomic
                     --active_interfaces;
                  } else {
                     // Some error has occured
                     if (verbose >= 0) {
                        fprintf(stderr, "Error: trap_send() returned %i (%s)\n", ret, trap_last_error_msg);
                        fprintf(stderr, "   Message skipped...\n");
                     }
                     read_next = 1;
                  }
               } else {
                  read_next = 1;
                  actual_min_timestamp = 0;
               }
            }
         }
      }

      if (!active_interfaces){
         trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, timeout);
//       usleep(INACTIVE_USLEEP_TIME);
//       private_stop = 1;
      }
   } // end while(!stop && !private_stop)

   if (verbose >= 1) {
      printf("Thread %i exitting.\n", index);
   }
}

/**
 * Basic capture thread - handles data incomming from on one interface.
 *
 * @param [in] index Index of the given link.
 */
void capture_thread(int index)
{
   int private_stop = 0;
   int ret, fail = 0;
   const void *rec;
   uint16_t rec_size;
   void *data_out = NULL;
   uint8_t data_fmt = TRAP_FMT_UNKNOWN;
//   int timeout = initial_timeout;

   if (verbose >= 1) {
      printf("Thread %i started.\n", index);
   }

//   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, timeout);
   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_WAIT);

   // Read data from input and log them to a file
   while (!stop && !private_stop) {
      if (verbose >= 2) {
         printf("Thread %i: calling trap_recv()\n", index);
      }
      // Receive data from index-th input interface, wait until data are available

      ret = trap_recv(index, &rec, &rec_size);
      //update output template
      if (ret == TRAP_E_OK || ret == TRAP_E_FORMAT_CHANGED) {
         if (ret == TRAP_E_FORMAT_CHANGED) {
            const char *spec = NULL;
            if (trap_get_data_fmt(TRAPIFC_INPUT, index, &data_fmt, &spec) != TRAP_E_OK) {
               fprintf(stderr, "Data format was not loaded.");
               return;
            } else {
               if (data_out != NULL) {
                  free (data_out);
                  data_out = NULL;
               }
               #pragma omp critical
               {
                  in_template[index] = ur_define_fields_and_update_template(spec, in_template[index]);
                  if (in_template[index] == NULL) {
                     fprintf(stderr, "Template could not be edited");
                     fail = 1;
                  } else {
                     out_template = ur_expand_template(spec, out_template);
                     char * spec_cpy = ur_template_string(out_template);
                     if (spec_cpy == NULL) {
                        fprintf(stderr, "Memory allocation problem.");
                        fail = 1;
                     }
                     trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec_cpy);
                  }

                  data_out = ur_create_record(out_template, UR_MAX_SIZE);
                  if (data_out == NULL) {
                     fprintf(stderr, "ERROR: Allocation of record\n");
                     fail = 1;
                  }               
               }
               if (fail == 1) {
                  break;
               }
               memset(data_out, 0, UR_MAX_SIZE);
            }
         }

         if (verbose >= 2) {
            printf("Thread %i: received %hu bytes of data\n", index, rec_size);
         }

         // Check size of received data
         if (rec_size < ur_rec_fixlen_size(in_template[index])) {
            if (rec_size <= 1) {
               if (verbose >= 0) {
                  printf("Interface %i received ending record, the interface will be closed.\n", index);
               }
               private_stop = 1;
               if (--active_interfaces > 0){// Only last thread send terminating message.
                  break;
               } else {
                  char dummy[1] = {0};
                  trap_send(0, dummy, 1); // FIXME: zero-length messages doesn't work, send message of length 1
                  break;
               }
            } else {
               fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                       ur_rec_fixlen_size(in_template[index]), rec_size);
               break;
            }
         }
      
         ur_copy_fields(out_template, data_out, in_template[index], rec);

         #pragma omp critical
         {
            ret = trap_send(0, data_out, ur_rec_size(out_template, data_out));
            if (ret != TRAP_E_OK) {
               if (ret == TRAP_E_TERMINATED) {
                  private_stop = 1; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
               } else {
                  // Some error has occured
                  fprintf(stderr, "Error: trap_send() returned %i (%s)\n", ret, trap_last_error_msg);
                  private_stop = 1;
               }
            }
         } // end critical section
      } else {
         TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
      }
   } // end while(!stop && !private_stop)

   if (verbose >= 1) {
      printf("Thread %i exitting.\n", index);
   }

}

int main(int argc, char **argv)
{
   int ret;
   char *out_template_str = NULL;
   int mode = MODE_TIME_IGNORE;
   int n_inputs = 0;

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

   if (verbose >= 0){
      printf("Verbosity level: %i\n", trap_get_verbose_level());
   }

   // Parse remaining parameters and get configuration
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'F':
            timestamp_selector = TS_FIRST;
            break;
         case 'n':
            n_inputs = atoi(optarg);
            break;
         case 'u':
            out_template_str = optarg;
            break;
         case 't':
            initial_timeout = atoi(optarg) * 1000000; // microseconds to seconds
            break;
         case 'T':
            mode=MODE_TIME_AWARE;
            break;
         default:
            fprintf(stderr, "Error: Invalid arguments.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 1;
      }
   }

   if (n_inputs == 0){
      fprintf(stderr, "Error: Missing number of input links (parameter -n CNT).\n");
      ret = -1;
      goto exit;
   } else if (n_inputs > 32) {
      fprintf(stderr, "Error: More than 32 interfaces is not allowed by TRAP library.\n");
      ret = -1;
      goto exit;
   }

   if (verbose >= 0) {
      printf("Number of inputs: %i\n", n_inputs);

      printf("Creating UniRec templates ...\n");
   }


   // ***** TRAP initialization *****
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
      ret = -3;
      goto exit;
   }

   // Create input and output UniRec template

   in_template = (ur_template_t**) calloc (sizeof(ur_template_t*), n_inputs);
   if (in_template == NULL) {
      fprintf(stderr, "Error: allocation of templates.\n");
      ret = -1;
      goto exit;
   }
   for (int i = 0; i < n_inputs; i++) {
      in_template[i] = ur_create_input_template(i, "", NULL);
      if (in_template[i] == NULL) {
         fprintf(stderr, "Error: Invalid input template %d", i);
         ret = -2;
         goto exit;
      }
   }
   if (out_template_str != NULL) {
      if (ur_define_set_of_fields(out_template_str) != UR_OK) {
         fprintf(stderr, "Error: output template format is not accurate.\n \
It should be: \"type1 name1,type2 name2,...\".\n \
Name of field may be any string matching the reqular expression [A-Za-z][A-Za-z0-9_]*\n\
Available types are: int8, int16, int32, int64, uint8, uint16, uint32, uint64, char,\
 float, double, ipaddr, time, string, bytes");
         ret = -2;
         goto exit;
      }
      char *f_names = ur_ifc_data_fmt_to_field_names(out_template_str);
      out_template = ur_create_output_template(0, out_template_str, NULL);
      free(f_names);
      if (out_template == NULL) {
         fprintf(stderr, "Memory allocation error\n");
         ret = -1;
         goto exit;
      }
   }
   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

// trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, "0");


   if (verbose >= 0) {
      printf("Initialization done.\n");
   }

   active_interfaces = n_inputs;

    // ***** Start a thread for each interface *****
   #pragma omp parallel num_threads(n_inputs)
   {
      if (mode == MODE_TIME_AWARE)
         ta_capture_thread(omp_get_thread_num());
      else
         capture_thread(omp_get_thread_num());
   }

   ret = 0;

   // ***** Cleanup *****
   if (verbose >= 0) {
      printf("Exitting ...\n");
   }
   if (in_template != NULL) {
      for (int i = 0; i < n_inputs; i++) {
         ur_free_template(in_template[i]);
      }
      free(in_template);
   }
   ur_free_template(out_template);

exit:
   // Do all necessary cleanup before exiting
   ur_finalize();
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return ret;
}
// END OF merger.c
