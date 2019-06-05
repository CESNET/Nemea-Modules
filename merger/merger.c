/**
 * \file merger.c
 * \brief Merge traffic incoming on mutiple interfaces into one output stream.
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2019
 */
/*
 * Copyright (C) 2019 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("merger","This module merges traffic from multiple input interfaces to one output stream (on one interface).",-1,1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "unirec", "UniRec specifier of input/output data (same to all links). (default <COLLECTOR_FLOW>).", required_argument, "string") \
  PARAM('n', "noeof", "Do not send termination message.", no_argument, "none") \
  PARAM('I', "ignore-in-eof", "Do not terminate on incomming termination message.", no_argument, "none")

static int stop = 0;
static int verbose;
static int noeof = 0;
static int ignoreineof = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

static ur_template_t **in_template; // UniRec template of input interface(s)
static ur_template_t *out_template; // UniRec template of output interface
static void *out_rec = NULL;

pthread_mutex_t unirec_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t *thr_list = NULL;
char *thr_init = NULL;

/**
 * Capture thread to receive incomming messages and send them via shared output interface.
 *
 * @param [in] index Index of the given link.
 */
void *capture_thread(void *arg)
{
   int index = *((int *) arg);
   int private_stop = 0;
   int ret;
   const void *rec;
   uint16_t rec_size;
   uint8_t data_fmt = TRAP_FMT_UNKNOWN;

   if (verbose >= 1) {
      fprintf(stderr, "Thread %i started.\n", index);
   }

   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_WAIT);

   // Read data from input and log them to a file
   while (!stop && !private_stop) {
      if (verbose >= 2) {
         printf("Thread %i: calling trap_recv()\n", index);
      }
      // Receive data from index-th input interface, wait until data are available

      ret = trap_recv(index, &rec, &rec_size);

      if (ret != TRAP_E_OK && ret != TRAP_E_FORMAT_CHANGED) {
         TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break)
      }
      if (verbose >= 2) {
         printf("Thread %i: received %hu bytes of data\n", index, rec_size);
      }

      // Check size of received data
      if (rec_size <= 1) {
         if (verbose >= 0) {
            fprintf(stderr, "Interface %i received ending record, the interface will be closed.\n", index);
         }
         if (!ignoreineof) {
            private_stop = 1;
            break;
         }
      } else if (rec_size < ur_rec_fixlen_size(in_template[index])) {
         fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
               ur_rec_fixlen_size(in_template[index]), rec_size);
         break;
      }

      /* critical section of UniRec manipulation */
      pthread_mutex_lock(&unirec_mutex);
      //update output template
      if (ret == TRAP_E_FORMAT_CHANGED) {
         const char *spec = NULL;
         if (trap_get_data_fmt(TRAPIFC_INPUT, index, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Data format was not loaded.");
            goto unlock_exit;
         } else {
            if (out_rec != NULL) {
               free(out_rec);
               out_rec = NULL;
            }

            in_template[index] = ur_define_fields_and_update_template(spec, in_template[index]);
            if (in_template[index] == NULL) {
               fprintf(stderr, "Template could not be edited");
               goto unlock_exit;
            } else {
               out_template = ur_expand_template(spec, out_template);
               char *spec_cpy = ur_template_string(out_template);
               if (spec_cpy == NULL) {
                  fprintf(stderr, "Memory allocation problem.");
                  goto unlock_exit;
               }
               trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec_cpy);
            }

            out_rec = ur_create_record(out_template, UR_MAX_SIZE);
            if (out_rec == NULL) {
               fprintf(stderr, "ERROR: Allocation of record failed.\n");
               goto unlock_exit;
            }
         }
      } else {
         /* normal message, clear the previous one */
         memset(out_rec, 0, ur_rec_size(out_template, out_rec));
      }

      ur_copy_fields(out_template, out_rec, in_template[index], rec);

      ret = trap_send(0, out_rec, ur_rec_size(out_template, out_rec));
      pthread_mutex_unlock(&unirec_mutex);
      /* end of critical section of UniRec manipulation */

      if (ret != TRAP_E_OK) {
         if (ret != TRAP_E_TERMINATED) {
            // Some error has occured
            fprintf(stderr, "Error: trap_send() returned %i (%s)\n", ret, trap_last_error_msg);
         }
         private_stop = 1; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
         break;
      }

   } // end while(!stop && !private_stop)

   if (verbose >= 1) {
      printf("Thread %i exiting.\n", index);
   }

   pthread_exit(NULL);
   return NULL;

unlock_exit:
   pthread_mutex_unlock(&unirec_mutex);
   pthread_exit(NULL);
   return NULL;
}

int main(int argc, char **argv)
{
   int ret, i;
   char *out_template_str = NULL;
   //int mode = MODE_TIME_IGNORE;

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
      case 'u':
         out_template_str = optarg;
         break;
      case 'n':
         noeof = 1;
         break;
      case 'I':
         ignoreineof = 1;
         break;
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
      ret = -3;
      goto exit;
   }

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

   if (module_info->num_ifc_in > 32) {
      fprintf(stderr, "Error: More than 32 interfaces is not allowed by TRAP library.\n");
      ret = -1;
      goto exit;
   }

   if (verbose >= 0) {
      printf("Number of inputs: %i\n", module_info->num_ifc_in);

      printf("Creating UniRec templates ...\n");
   }

   // Create input and output UniRec template

   in_template = (ur_template_t **) calloc(sizeof(ur_template_t *), module_info->num_ifc_in);
   if (in_template == NULL) {
      fprintf(stderr, "Error: allocation of templates failed.\n");
      ret = -1;
      goto exit;
   }

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   if (verbose >= 0) {
      printf("Initialization done.\n");
   }

   const void **msgs = calloc(module_info->num_ifc_in, sizeof(msgs[0]));
   uint16_t *msgs_size = calloc(module_info->num_ifc_in, sizeof(msgs_size[0]));

   if (msgs == NULL || msgs_size == NULL) {
      free(msgs); /* could be successfully allocated */
      goto exit;
   }

   out_template = NULL;

   /* Start with user-defined template given by -u parameter */
   if (out_template_str != NULL) {
      if (ur_define_set_of_fields(out_template_str) != UR_OK) {
         fprintf(stderr, "Error: output template format is not accurate.\n"
                         "It should be: \"type1 name1,type2 name2,...\".\n"
                         "Name of field may be any string matching the reqular expression [A-Za-z][A-Za-z0-9_]*\n"
                         "Available types are: int8, int16, int32, int64, uint8, uint16, uint32, uint64, char,"
                         "float, double, ipaddr, time, string, bytes");
         ret = -2;
         goto exit;
      }
      char *f_names = ur_ifc_data_fmt_to_field_names(out_template_str);
      out_template = ur_create_output_template(0, f_names, NULL);
      free(f_names);
      if (out_template == NULL) {
         fprintf(stderr, "Memory allocation error\n");
         ret = -1;
         goto exit;
      }
   }
   
   /* Receive first message via each input IFC to get sent data format and extend output template */
   for (i = 0; i < module_info->num_ifc_in; ++i) {
      trap_set_required_fmt(i, TRAP_FMT_UNIREC, "");
      TRAP_RECEIVE(i, msgs[i], msgs_size[i], in_template[i]);

      const char *spec = NULL;
      uint8_t data_fmt;
      if (trap_get_data_fmt(TRAPIFC_INPUT, i, &data_fmt, &spec) != TRAP_E_OK) {
         fprintf(stderr, "Data format was not loaded.");
         goto exit;
      } else {
         if ((out_template = ur_expand_template(spec, out_template)) == NULL) {
            fprintf(stderr, "Failed to prepare output template.\n");
            goto exit;
         }
      }
   }

   /* Set data format to output IFC to allow sending */
   ur_set_output_template(0, out_template);

   /* Prepare local UniRec message to send captured first messages */
   out_rec = ur_create_record(out_template, UR_MAX_SIZE);

   for (i = 0; i < module_info->num_ifc_in; ++i) {
      ur_copy_fields(out_template, out_rec, in_template[i], msgs[i]);
      trap_send(0, out_rec, ur_rec_size(out_template, out_rec));
   }
   free(msgs);
   free(msgs_size);


   /* Prepare list of threads */
   thr_list = calloc(module_info->num_ifc_in, sizeof(thr_list[0]));
   thr_init = calloc(module_info->num_ifc_in, sizeof(thr_init[0]));

   if (thr_list == NULL || thr_init == NULL) {
      goto exit_clean_template;
   }

   /* Start a thread for each interface that will receive messages and send
    * them via common output IFC */
   for (i = 0; i < module_info->num_ifc_in; ++i) {
      if (pthread_create(&thr_list[i], NULL, capture_thread, &i) != 0) {
         fprintf(stderr, "Interrupted creation of threads due to failure.\n");
         break;
      }
      thr_init[i] = 1;
   }

   for (i = 0; i < module_info->num_ifc_in; ++i) {
      if (thr_init[i] == 1 && pthread_join(thr_list[i], NULL) != 0) {
         /* error */
         fprintf(stderr, "Error: could not join thread %d.\n", i);
      }
   }

   ret = 0;

   // ***** Cleanup *****
   if (verbose >= 0) {
      fprintf(stderr, "Exiting ...\n");
   }

   if (!noeof) {
      char dummy[1] = {0};
      trap_send(0, dummy, 1);
      trap_send_flush(0);
   }

exit_clean_template:
   if (in_template != NULL) {
      for (i = 0; i < module_info->num_ifc_in; i++) {
         ur_free_template(in_template[i]);
      }
      free(in_template);
   }
   ur_free_template(out_template);

exit:
   // Do the remaining cleanup before exiting
   ur_finalize();
   TRAP_DEFAULT_FINALIZATION()
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   free(thr_list);
   free(thr_init);

   return ret;
}

// Local variables:
// c-basic-offset: 3;
// End:
