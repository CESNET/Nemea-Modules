/**
 * \file bloom_functions.c
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

#include "blooming_history_functions.h"


int is_from_prefix(ip_addr_t *ip, ip_addr_t *protected_prefix, int32_t protected_prefix_length)
{
   // Both IPv4
   if(ip_is4(ip) && ip_is4(protected_prefix)) {
      uint32_t mask = 0xffffffff << (32 - protected_prefix_length);
      return (ip_get_v4_as_int(ip) & mask) == (ip_get_v4_as_int(protected_prefix) & mask);
   }
   // Both IPv6
   if (ip_is6(ip) && ip_is6(protected_prefix)) {
      int bytes_match;

      // Compare whole bytes
      bytes_match = memcmp((const char *) ip, (const char *) protected_prefix, protected_prefix_length / 8) == 0;

      // Compare remaining byte
      if (bytes_match && protected_prefix_length % 8 != 0) {
         int byte_index = protected_prefix_length / 8;
         uint8_t mask = 0xff << (8 - (protected_prefix_length % 8));

         return bytes_match && ((ip->bytes[byte_index] & mask) == (protected_prefix->bytes[byte_index] & mask));
      }

      return bytes_match;
   }

   return 0;
}


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

