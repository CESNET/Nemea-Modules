/**
 * \file bloom_functions.c
 * \brief History of communicating entities using bloom filters.
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include <curl/curl.h>
#include <unirec/unirec.h>

#include "bloom.h"
#include "bloom_history.h"
#include "bloom_history_config.h"
#include "bloom_history_functions.h"


extern int stop;
extern int32_t UPLOAD_INTERVAL;
extern pthread_mutex_t MUTEX_BLOOM_SWAP;
extern pthread_mutex_t MUTEX_TIMER_STOP;
extern pthread_cond_t CV_TIMER_STOP;


int curl_init_handle(CURL **curl)
{
   *curl = curl_easy_init();

   if (!(*curl)) {
      return -1;
   }

   // None of the following calls should fail (apart from OOM)
   // POST request method
   curl_easy_setopt(*curl, CURLOPT_POST, 1L);
   // follow redirections
   curl_easy_setopt(*curl, CURLOPT_FOLLOWLOCATION, 1L);
   curl_easy_setopt(*curl, CURLOPT_MAXREDIRS, 50L);
   // enable verbose for easier tracing
   curl_easy_setopt(*curl, CURLOPT_VERBOSE, 1L);
   // 60 seconds timeout - cuases SIGALARM (this might not be a good idea)
   // curl_easy_setopt(handle, CURLOPT_TIMEOUT, 60L);
   curl_easy_setopt(*curl, CURLOPT_TCP_KEEPALIVE, 1L);

   return 0;
}


int curl_send_bloom(CURL *curl, const char *aggregator_service_url, const struct bloom *bloom_filter)
{
   int error = 0;
   long code;
   CURLcode res;

   uint8_t *buffer = NULL;
   int32_t buffer_size;
   struct curl_slist *list = NULL;

   if(!curl) {
      return -3;
   }

   error = bloom_serialize(bloom_filter, &buffer, &buffer_size);
   if (error) {
      return error;
   }

   list = curl_slist_append(list, "Content-Type: application/octet-stream");
   // TODO Disable "Expect:" header - saves about 100ms on small POSTs - gzip?
   /* list = curl_slist_append(list, "Expect:"); */
   // TODO curl does not compress anything for us
   /* list = curl_slist_append(list, "Content-Encoding: gzip"); */

   /* set url */
   curl_easy_setopt(curl, CURLOPT_URL, aggregator_service_url);
   /* specify POST data */
   curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buffer);
   /* libcurl will strlen() by itself otherwise */
   curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) buffer_size);
   curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

   res = curl_easy_perform(curl);
   if (res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      error = -4;
   }

   curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
   if (code != 200L) {
      error = -5;
   }

   curl_slist_free_all(list);
   bloom_free_serialized_buffer(&buffer);

   return error;
}


void curl_free_handle(CURL **curl)
{
   curl_easy_cleanup(*curl);
   *curl = NULL;
}

/**
 * Entry point for timer thread.
 *
 * Periodically uploads and renews BLOOM bloom filter.
 *
 * \param[in] struct bloom_history_config *config_
*/
void *pthread_entry_upload(void *config_)
{
   struct bloom_history_config *config = (struct bloom_history_config *)config_;
   CURL *curl = NULL;
   curl_init_handle(&curl);

   while (!stop) {
      struct timespec ts;
      uint64_t timestamp_from, timestamp_to;

      // This is the actuall "sleeping" (gets woken up on module stop)
      pthread_mutex_lock(&MUTEX_TIMER_STOP);
      clock_gettime(CLOCK_REALTIME, &ts);
      timestamp_from = ts.tv_sec;
      ts.tv_sec += UPLOAD_INTERVAL;
      pthread_cond_timedwait(&CV_TIMER_STOP, &MUTEX_TIMER_STOP, &ts);
      pthread_mutex_unlock(&MUTEX_TIMER_STOP);

      for (int i = 0; i < config->size; i++) {
         struct bloom *bloom_new, *bloom_send;
         char *url = NULL;
         int curl_error = 0, asprintf_error = 0, bloom_init_error = 0;
         uint32_t id = config->id[i];

         // Create empty bloom
         bloom_new = calloc(1, sizeof(struct bloom));
         bloom_init(bloom_new, config->bloom_entries[i], config->bloom_fp_error_rate[i]);
         if (bloom_init_error != 0) {
            fprintf(stderr, "Error(%d): bloom init failed\n", asprintf_error);
            exit(1);
         }

         // Read consistent state
         pthread_mutex_lock(&MUTEX_BLOOM_SWAP);
         bloom_send = config->bloom_list[id];
         config->bloom_list[id] = bloom_new;
         pthread_mutex_unlock(&MUTEX_BLOOM_SWAP);

         clock_gettime(CLOCK_REALTIME, &ts);
         timestamp_to = ts.tv_sec + 1; // +1: In case EOF is sent immediately after start

         // Compose endpoint url
         asprintf_error = asprintf(&url, "%s/%ld/%ld/", config->api_url[i], timestamp_from, timestamp_to);
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

      }
   }

   curl_free_handle(&curl);

   return NULL;
}
