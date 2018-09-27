/**
 * \file blooming_history.c
 * \brief History of communicating entities using bloom filters.
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2013,2014,2015,2016,2017,2018 CESNET
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

#define _GNU_SOURCE

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <curl/curl.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "blooming_history_functions.h"
#include "fields.h"
#include "bloom.h"


UR_FIELDS (
   ipaddr SRC_IP,
   ipaddr DST_IP
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("History gathering module", \
        "This module gathers history of communicating entities and stores them in a bloom filter.", 1, 0)

#define MODULE_PARAMS(PARAM) \
   PARAM('n', "number", "Expected number of distinct entries (ip addresess) for expected "          \
                        "aggregation period. For example the upload <interval> is set to 5min, "    \
                        "but we will want to aggregate over 2 weeks period from the Aggregator "    \
                        "service).", required_argument, "int32")                                    \
   PARAM('e', "error", "False positive error rate of the underlying Bloom filter at <number> "      \
                        "entries.", required_argument, "float")                                     \
   PARAM('p', "prefix", "Protected IP prefix. Only communication with addresses from this prefix "  \
                        "will be recorded in the Bloom filter.", required_argument, "string")       \
   PARAM('t', "interval", "Interval in seconds, after which an old Bloom filter is sent to the "    \
                          "Aggregator service and replaced by a new empty filter.",                 \
                          required_argument, "int32")                                               \
   PARAM('s', "service", "IP address of the Aggregator service. Bloom filter will be sent to this " \
                         "service via HTTP POST each <interval> seconds.", required_argument,       \
                         "string")

static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


/**
* Bloom filter maximal number of entries at false positive specified error
*/
int32_t ENTRIES = 1000000;

/**
* Bloom filter false positive error at ENTRIES distinct entries
*/
double FP_ERROR_RATE = 0.01;

/**
* Protected IP prefix
*/
ip_addr_t PROTECTED_PREFIX;

/**
* Protected IP prefix length
*/
int32_t PROTECTED_PREFIX_LENGTH = 0;

/**
* URI of Aggregator service
*/
char *AGGREGATOR_SERVICE = NULL;

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
pthread_cond_t    CV_TIMER_STOP = PTHREAD_COND_INITIALIZER;

/**
* Current bloom filter
*/
struct bloom *BLOOM;


/**
 * Entry point for timer thread.
 *
 * Periodically uploads and renews BLOOM bloom filter.
 *
 * \param[in]  attr   Not used.
*/
void *pthread_entry_upload(void *attr)
{
   struct timespec ts;
   struct bloom *bloom_new;
   struct bloom *bloom_send;
   CURL *curl = NULL;
   char *url = NULL;
   uint64_t timestamp_from, timestamp_to;

   curl_init_handle(&curl);

   while (!stop) {
      int curl_error = 0, asprintf_error = 0;

      // This is the actuall "sleeping" (gets woken up on module stop)
      pthread_mutex_lock(&MUTEX_TIMER_STOP);
      clock_gettime(CLOCK_REALTIME, &ts);
      timestamp_from = ts.tv_sec;
      ts.tv_sec += UPLOAD_INTERVAL;
      pthread_cond_timedwait(&CV_TIMER_STOP, &MUTEX_TIMER_STOP, &ts);

      // Create empty bloom
      bloom_new = calloc(1, sizeof(struct bloom));
      bloom_init(bloom_new, ENTRIES, FP_ERROR_RATE);

      // Read consistent state
      pthread_mutex_lock(&MUTEX_BLOOM_SWAP);
      bloom_send = BLOOM;
      BLOOM = bloom_new;
      pthread_mutex_unlock(&MUTEX_BLOOM_SWAP);

      clock_gettime(CLOCK_REALTIME, &ts);
      timestamp_to = ts.tv_sec;

      // Compose endpoint url
      asprintf_error = asprintf(&url, "%s/%ld/%ld/", AGGREGATOR_SERVICE, timestamp_from, timestamp_to);
      if (asprintf_error < 0) {
         fprintf(stderr, "Error(%d): memory allocation failed\n", asprintf_error);
         exit(1);
      }

      // Send to the service
      curl_error = curl_send_bloom(curl, url, bloom_send);
      if (curl_error) {
         fprintf(stderr, "Error(%d): sending filter\n", curl_error);
      }

      bloom_free(bloom_send);
      free(bloom_send);
      free(url);

      pthread_mutex_unlock(&MUTEX_TIMER_STOP);
   }

   curl_free_handle(&curl);

   return NULL;
}


int main(int argc, char **argv)
{
   signed char opt;
   int error = 0;
   pthread_t pthread_upload;

   /* TRAP initialization */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'n':
         ENTRIES = atoi(optarg);
         if (ENTRIES < 1000) {
            fprintf(stderr, "Error: Number of entries must be > 1000\n");
            error = 1;
         }
         break;
      case 'e':
         FP_ERROR_RATE = atof(optarg);
         if (FP_ERROR_RATE < 0 || FP_ERROR_RATE > 1) {
            fprintf(stderr, "Error: False-positive rate must be from (0, 1) interval\n");
            error = 1;
         }
         break;
      case 'p':
         {
            char *prefix_slash = strchr(optarg, '/');

            if (prefix_slash == NULL) {
               error = 1;
               break;
            }

            *prefix_slash = '\0';
            if (!ip_from_str(optarg, &PROTECTED_PREFIX)) {
               fprintf(stderr, "Error: Invalid protected prefix format\n");
               error = 1;
               break;
            }

            PROTECTED_PREFIX_LENGTH = atoi(prefix_slash + 1);
         }
         break;
      case 't':
         UPLOAD_INTERVAL = atoi(optarg);
         if (UPLOAD_INTERVAL <= 0) {
            fprintf(stderr, "Error: Uload interval must be > 0\n");
            error = 1;
         }
         break;
      case 's':
         AGGREGATOR_SERVICE = optarg;
         break;
      default:
         error = 1;
      }
   }

   if (error) {
      fprintf(stderr, "Error: Invalid arguments.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }


#ifdef DEBUG
   {
      char protected_ip_prefix_str[INET6_ADDRSTRLEN];
      ip_to_str(&PROTECTED_PREFIX, protected_ip_prefix_str);
      printf("ENTRIES:%d, fpr:%f, prefix:%s, prefix_length:%d, interval:%d, service:%s\n",
            ENTRIES, FP_ERROR_RATE, protected_ip_prefix_str, PROTECTED_PREFIX_LENGTH, UPLOAD_INTERVAL, AGGREGATOR_SERVICE);
   }
#endif // DEBUG

   /* Initialize libcurl */
   curl_global_init(CURL_GLOBAL_ALL);

   /* Alloc and initialize new bloom */
   BLOOM = calloc(1, sizeof(struct bloom));
   bloom_init(BLOOM, ENTRIES, FP_ERROR_RATE);

   /* Setup upload thread */
   error = pthread_create(&pthread_upload, NULL, pthread_entry_upload, NULL);
   if (error) {
      fprintf(stderr, "Error: Failed to create timer thread.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   /* Create UniRec templates */
   ur_template_t *in_tmplt = ur_create_input_template(0, "SRC_IP,DST_IP", NULL);
   if (in_tmplt == NULL) {
      fprintf(stderr, "Error: Input template could not be created.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   /* Main processing loop */
   while (!stop) {
      int ret;
      const void *in_rec;
      uint16_t in_rec_size;
      ip_addr_t src_ip, dst_ip;

      int is_from_prefix_src, is_from_prefix_dst;
      ip_addr_t *ip = NULL;


      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                  ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      src_ip = ur_get(in_tmplt, in_rec, F_SRC_IP);
      dst_ip = ur_get(in_tmplt, in_rec, F_DST_IP);

      is_from_prefix_src = is_from_prefix(&src_ip, &PROTECTED_PREFIX, PROTECTED_PREFIX_LENGTH);
      is_from_prefix_dst = is_from_prefix(&dst_ip, &PROTECTED_PREFIX, PROTECTED_PREFIX_LENGTH);

      if (is_from_prefix_src && !is_from_prefix_dst) {
         ip = &dst_ip;
      } else if (!is_from_prefix_src && is_from_prefix_dst) {
         ip = &src_ip;
      } else {
         continue;
      }

#ifdef DEBUG
      {
         char src_ip_str[INET6_ADDRSTRLEN];
         char dst_ip_str[INET6_ADDRSTRLEN];
         char add_ip_str[INET6_ADDRSTRLEN];
         ip_to_str(&src_ip, src_ip_str);
         ip_to_str(&dst_ip, dst_ip_str);
         ip_to_str(ip, add_ip_str);
         printf("src_ip:%s, dst_ip:%s, added_ip:%s\n", src_ip_str, dst_ip_str, add_ip_str);
      }
#endif // DEBUG

      if (ip_is4(ip)) {
         pthread_mutex_lock(&MUTEX_BLOOM_SWAP);
         bloom_add(BLOOM, ip_get_v4_as_bytes(ip), 4);
         pthread_mutex_unlock(&MUTEX_BLOOM_SWAP);
      } else {
         pthread_mutex_lock(&MUTEX_BLOOM_SWAP);
         bloom_add(BLOOM, ip->ui8, 16);
         pthread_mutex_unlock(&MUTEX_BLOOM_SWAP);
      }
   }

   /* Wait for timer thread */
   pthread_mutex_lock(&MUTEX_TIMER_STOP);
   pthread_cond_signal(&CV_TIMER_STOP);
   pthread_mutex_unlock(&MUTEX_TIMER_STOP);

   pthread_join(pthread_upload, NULL);

   /* Cleanup */
   bloom_free(BLOOM);
   free(BLOOM);

   curl_global_cleanup();

   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   ur_free_template(in_tmplt);
   ur_finalize();

   return 0;
}

