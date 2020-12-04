/**
 * \file bloom_history.c
 * \brief History of communicating entities using bloom filters.
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "bloom.h"
#include "bloom_history.h"
#include "bloom_history_config.h"
#include "bloom_history_functions.h"
#include "fields.h"


trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("bloom_history", \
        "This module gathers history of communicating entities and stores them in a bloom filter.", 1, 0)

#define MODULE_PARAMS(PARAM) \
   PARAM('c', "config", "Configuration file.", required_argument, "string") \
   PARAM('t', "interval", "Interval in seconds, after which an old Bloom filter is sent to the "    \
                          "Aggregator service and replaced by a new empty filter.",                 \
                          required_argument, "int32")


/**
* Controls execution of the main receive loop
*/
int stop = 0;
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
* Interval between bloom filter upload to Aggregator service
*/
int32_t UPLOAD_INTERVAL = 300;

/**
*  Guards clean replacement of current bloom for a new one before upload
*/
pthread_mutex_t MUTEX_BLOOM_SWAP = PTHREAD_MUTEX_INITIALIZER;

/**
*  Guards proper upload thread termination
*/
pthread_mutex_t MUTEX_TIMER_STOP = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t CV_TIMER_STOP = PTHREAD_COND_INITIALIZER;


int bloom_history(struct bloom_history_config *config)
{
   int error = 0;
   pthread_t pthread_upload;
   ur_template_t *template_input = NULL;

   /* Setup upload thread */
   error = pthread_create(&pthread_upload, NULL, pthread_entry_upload, config);
   if (error) {
      fprintf(stderr, "Error: Failed to create timer thread.\n");
      error = -1;
      goto cleanup;
   }

   /* Create UniRec templates */
   template_input = ur_create_input_template(INTERFACE_IN, "", NULL); // Does not matter, will be updated
   if (template_input == NULL) {
      fprintf(stderr, "Error: Input template could not be created.\n");
      error = -1;
      goto cleanup;
   }

   /* Main processing loop */
   while (!stop) {
      const void *data_in = NULL;
      uint16_t data_in_size = 0;

      int recv_error = TRAP_RECEIVE(INTERFACE_IN, data_in, data_in_size, template_input);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(recv_error, continue, error = -2; goto cleanup_pthread);

      if (data_in_size < ur_rec_fixlen_size(template_input)) {
         if (data_in_size <= 1) {
            stop = 1;
            break; // End of data
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                  ur_rec_fixlen_size(template_input), data_in_size);
            break;
         }
      }

      /* Get ip prefix tag and see if we have configuration for it */
      uint32_t prefix_tag = ur_get(template_input, data_in, F_PREFIX_TAG);

      if (prefix_tag < config->bloom_list_size && config->bloom_list[prefix_tag] != NULL) {
         ip_addr_t dst_ip = ur_get(template_input, data_in, F_DST_IP);

         if (ip_is4(&dst_ip)) {
            pthread_mutex_lock(&MUTEX_BLOOM_SWAP);
            bloom_add(config->bloom_list[prefix_tag], ip_get_v4_as_bytes(&dst_ip), 4);
            pthread_mutex_unlock(&MUTEX_BLOOM_SWAP);
         } else {
            pthread_mutex_lock(&MUTEX_BLOOM_SWAP);
            bloom_add(config->bloom_list[prefix_tag], dst_ip.ui8, 16);
            pthread_mutex_unlock(&MUTEX_BLOOM_SWAP);
         }
      } else {
         fprintf(stderr, "Error: Received unknown PREFIX_TAG: %u\n", prefix_tag);
         continue;
      }
   }

cleanup_pthread:
   /* Wait for timer thread */
   pthread_mutex_lock(&MUTEX_TIMER_STOP);
   pthread_cond_signal(&CV_TIMER_STOP);
   pthread_mutex_unlock(&MUTEX_TIMER_STOP);

   pthread_join(pthread_upload, NULL);

cleanup:
   ur_free_template(template_input);
   ur_finalize();

   return error;
}

int main(int argc, char **argv)
{
   int error = 0;
   signed char opt;

   struct bloom_history_config config;
   bloom_history_config_init(&config);

   /* TRAP initialization */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   errno = 0; // FIXME For some reason, ^^^ sets errno=2 when there is no error causing issues down the line
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   curl_global_init(CURL_GLOBAL_ALL);

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'c':
         error = bloom_history_parse_config(optarg, &config);
         debug_print("parse_config ret %d\n", error);
         if (error != 0) {
            error = -1;
            goto cleanup;
         }
         break;
      case 't':
         UPLOAD_INTERVAL = atoi(optarg);
         if (UPLOAD_INTERVAL <= 0) {
            fprintf(stderr, "Error: Uload interval must be > 0\n");
            error = -1;
            goto cleanup;
         }
         break;
      default:
         fprintf(stderr, "Error: Invalid arguments.\n");
         error = -1;
         goto cleanup;
      }
   }

   error = bloom_history(&config);

cleanup:
   curl_global_cleanup();

   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   bloom_history_config_free(&config);

   return error;
}
