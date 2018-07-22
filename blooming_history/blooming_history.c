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
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *   may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
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

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <bloom.h>

#include "blooming_history_functions.h"
#include "fields.h"


UR_FIELDS (
   ipaddr SRC_IP,
   ipaddr DST_IP
)

trap_module_info_t *module_info = NULL;

//BASIC(char *, char *, int, int)
#define MODULE_BASIC_INFO(BASIC) \
   BASIC("History gathering module", \
        "This module gathers history of communicating entities and stores them in a bloom filter.", 1, 0)

#define MODULE_PARAMS(PARAM) \
   PARAM('n', "number", "Expected number of distinct entries (addresess) for long aggregated period.", required_argument, "int32") \
   PARAM('e', "error", "False possitive error rate at \"count\" entries.", required_argument, "float") \
   PARAM('p', "prefix", "Protected IP prefix. Only communication with addresses from this prefix will be recorded", required_argument, "string") \
   PARAM('t', "interval", "Interval in seconds for periodic filter upload to the aggregator service.", required_argument, "int32") \
   PARAM('s', "service", "IP address of the aggregator service.", required_argument, "string")
   //PARAM(char, char *, char *, no_argument  or  required_argument, char *)

static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


struct bloom BLOOM;

int32_t ENTRIES = 1000000;
double FP_ERROR_RATE = 0.01;
ip_addr_t PROTECTED_PREFIX;
int32_t PROTECTED_PREFIX_LENGTH = 0;
int32_t UPLOAD_INTERVAL = 300;
char* AGGREGATOR_SERVICE = NULL;


int main(int argc, char **argv)
{
   signed char opt;
   int error = 0;
   
   /* TRAP initialization */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
 
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'n':
            ENTRIES = atoi(optarg);
            break;
         case 'e':
            FP_ERROR_RATE = atof(optarg);
            break;
         case 'p':
            {
               char* prefix_slash = strchr(optarg, '/');

               if (prefix_slash == NULL) {
                  error = 1;
                  break;
               }

               *prefix_slash = '\0';
               if (!ip_from_str(optarg, &PROTECTED_PREFIX)) {
                  error = 1; 
               }

               PROTECTED_PREFIX_LENGTH = atoi(prefix_slash + 1);
            }
            break;
         case 't':
            UPLOAD_INTERVAL = atoi(optarg);
            break;
         case 's':
            AGGREGATOR_SERVICE = optarg;
            break;
         default:
            error = 1;
      }
   }

   if (error) {
      fprintf(stderr, "Invalid arguments.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   /* TODO Argument verification
      prefix length <= ip type length
      fr_error_rate in (0,1)
      ENTRIES >= 1024 TODO check - libbloom limitation
      upload interval > 0
   */
   
   // {
   //    char protected_ip_prefix_str[INET6_ADDRSTRLEN];
   //    ip_to_str(&PROTECTED_PREFIX, protected_ip_prefix_str);
   //    printf("ENTRIES:%d, fpr:%f, prefix:%s, prefix_length:%d, interval:%d, service:%s\n", 
   //         ENTRIES, FP_ERROR_RATE, protected_ip_prefix_str, PROTECTED_PREFIX_LENGTH, UPLOAD_INTERVAL, AGGREGATOR_SERVICE);
   // }

   bloom_init(&BLOOM, ENTRIES, FP_ERROR_RATE);

   /* Create UniRec templates */
   ur_template_t *in_tmplt = ur_create_input_template(0, "SRC_IP,DST_IP", NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }

   /* Main processing loop */
   while (!stop) {
      int ret;
      const void *in_rec;
      uint16_t in_rec_size;
      ip_addr_t src_ip, dst_ip;

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

      /* TODO Process the data */
      {
         int is_from_prefix_src, is_from_prefix_dst;
         ip_addr_t* ip = NULL;

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

         // {
         //    char src_ip_str[INET6_ADDRSTRLEN];
         //    char dst_ip_str[INET6_ADDRSTRLEN];
         //    char add_ip_str[INET6_ADDRSTRLEN];
         //    ip_to_str(&src_ip, src_ip_str);
         //    ip_to_str(&dst_ip, dst_ip_str);
         //    ip_to_str(ip, add_ip_str);
         //    printf("src_ip:%s, dst_ip:%s, added_ip:%s\n", src_ip_str, dst_ip_str, add_ip_str);
         // }

         if (ip_is4(ip)) {
            bloom_add(&BLOOM, ip_get_v4_as_bytes(ip), 4);
         } else {
            bloom_add(&BLOOM, ip->ui8, 16); 
         }
      }
   }

   /* Cleanup */
   bloom_free(&BLOOM);

   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   ur_free_template(in_tmplt);
   ur_finalize();

   return 0;
}

