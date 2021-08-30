
/**
 * \file flow_scatter.c
 * \author Marek Svepes <svepemar@fit.cvut.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>


#define IP_BIT_FIELD_SRC  0x04
#define IP_BIT_FIELD_DST  0x02
#define IP_BIT_FIELD_PAIR  0x01

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define TRUE 1
#define FALSE 0

#define OUT_IFC_TIMEOUT TRAP_WAIT
#define OUT_IFC_FIELDS_HASH "uint8 IP_BIT_FIELD"

#define BASIC_IN_IFC_IDX  0

#define SRC_IP_DISTR  0
#define DST_IP_DISTR  1
#define PAIR_IP_DISTR  2

typedef union IP_pair {
   uint32_t u32[8];
   uint64_t u64[4];
} IP_pair_t;

typedef struct ports {
  uint16_t port1;
  uint16_t port2;
} ports_t;

typedef struct hashing {
    ports_t ports;
    IP_pair_t ips;
}hashing_t;

trap_module_info_t *module_info = NULL;


#define MODULE_BASIC_INFO(BASIC) \
  BASIC("flow_scatter", "This module splits received flow records between output interfaces." \
                        "It has two input interfaces - first one for basic flows, second one for flows with SIP information." \
                        "For each input interface it has N (module parameter) output interfaces and it splits flow records" \
                        "between them according to selected scattering method (R,L,H parameters).", 1, -1)

#define MODULE_PARAMS(PARAM) \
    PARAM('N', "nodes-num", "Number of output interfaces for every input interface.", required_argument, "uint8") \
    PARAM('H', "hash-distr", "Distribute the flow records using hashing.", no_argument, "none") \
    PARAM('L', "lines-distr", "Distribute the flow records according to line number.", no_argument, "none") \
    PARAM('R', "rand-distr", "Distribute the flow records randomly according to uniformly distributed node numbers.", no_argument, "none") \
    PARAM('S', "statistics", "Periodically prints statistics about flow distribution to stdout (argument determines length of the period in seconds).", required_argument, "uint32")

static int stop = 0;

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint16 SRC_PORT,
   uint16 DST_PORT
)

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

unsigned long nodes_num = 0;

/* Each thread saves statistics about flow distribution (array on every index can have different length, allocation during initialization) */
uint64_t cnts;
uint8_t verb = 0;
/* controls loop of the main thread */
uint8_t terminate = 0;
static char sendeof = 1;
/* ----------------------------------------------------------------------------- */
/* ----------------------------- HASHING FUNCTIONS ----------------------------- */


unsigned reverse(unsigned x)
{
   x = ((x & 0x55555555) <<  1) | ((x >>  1) & 0x55555555);
   x = ((x & 0x33333333) <<  2) | ((x >>  2) & 0x33333333);
   x = ((x & 0x0F0F0F0F) <<  4) | ((x >>  4) & 0x0F0F0F0F);
   x = (x << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | (x >> 24);
   return x;
}

unsigned int crc32a(char *message, int len)
{
   int i, j;
   unsigned int byte, crc;

   crc = 0xFFFFFFFF;
   for (i = 0; i < len; i++) {
      byte = message[i];            // Get next byte.
      byte = reverse(byte);         // 32-bit reversal.
      for (j = 0; j <= 7; j++) {    // Do eight times.
         if ((int)(crc ^ byte) < 0) {
           crc = (crc << 1) ^ 0x04C11DB7;
         } else {
           crc = crc << 1;
         }
         byte = byte << 1;          // Ready next msg bit.
      }
   }

   return reverse(~crc);
}

unsigned int crc32c_table[256];

void init_crc32c_table()
{
   int j;
   unsigned int byte, crc, mask;

   /* Set up the crc32c_table, if necessary. */

   for (byte = 0; byte <= 255; byte++) {
      crc = byte;
      for (j = 7; j >= 0; j--) {    // Do eight times.
         mask = -(crc & 1);
         crc = (crc >> 1) ^ (0xEDB88320 & mask);
      }
      crc32c_table[byte] = crc;
   }
}

INLINE unsigned int crc32c(char *message, int len)
{
   int i;
   unsigned int byte, crc;

   crc = 0xFFFFFFFF;
   for (i = 0; i < len; i++) {
      byte = message[i];
      crc = (crc >> 8) ^ crc32c_table[(crc ^ byte) & 0xFF];
   }

   return ~crc;
}



void traffic_repeater(void)
{
   int ret;
   uint16_t data_size;
   uint64_t cnt_r, cnt_s, cnt_t, diff;
   const void *data;
   struct timespec start, end;
   uint32_t pair_ip_node, hash;
   hashing_t hashing_struct;
   size_t pair_ip_len = 0;
   ip_addr_t *src_ip = NULL, *dst_ip = NULL;

   data_size = 0;
   cnt_r = cnt_s = cnt_t = 0;
   data = NULL;
   ur_template_t *in_tmplt = ur_create_input_template(BASIC_IN_IFC_IDX, "SRC_IP,DST_IP,SRC_PORT,DST_PORT", NULL);
   if (verb) {
      fprintf(stderr, "Info: Initializing traffic repeater...\n");
   }
  // clock_gettime(CLOCK_MONOTONIC, &start);

   //set NULL to required format on input interface
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, "ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT");

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   //main loop
   while (stop == 0) {
      ret = trap_recv(0, &data, &data_size);
      if (ret == TRAP_E_OK || ret == TRAP_E_FORMAT_CHANGED) {
         cnt_r++;
         if (ret == TRAP_E_OK) {
            if (data_size <= 1) {
               if (verb) {
                  fprintf(stderr, "Info: Final record received, terminating repeater...\n");
               }
               stop = 1;
            }
         } else {
            // Get the data format of senders output interface (the data format of the output interface it is connected to)
            const char *spec = NULL;
            int i = 0;
            uint8_t data_fmt = TRAP_FMT_UNKNOWN;
            if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
               fprintf(stderr, "Data format was not loaded.");
               return;
            }
            // Set the same data format to repeaters output interface
            for (i =0; i< nodes_num; i++)
            {
              trap_set_data_fmt(i, TRAP_FMT_UNIREC, spec);
            }
         }

         if (stop == 1 && sendeof == 0){
            /* terminating module without eof message */
            break;
         } else {
           src_ip = &ur_get(in_tmplt, data, F_SRC_IP);
           dst_ip = &ur_get(in_tmplt, data, F_DST_IP);

           hashing_struct.ports.port1 = MIN(ur_get(in_tmplt, data, F_SRC_PORT),ur_get(in_tmplt, data, F_DST_PORT));
           hashing_struct.ports.port2 = MAX(ur_get(in_tmplt, data, F_SRC_PORT),ur_get(in_tmplt, data, F_DST_PORT));

           if (src_ip == NULL || dst_ip == NULL) {
              fprintf(stderr, "Error: could not get SRC or DST IP field from received message.\n");
           }

           if (ip_is4(src_ip) == TRUE) {
               pair_ip_len = 2 * sizeof(uint32_t);
               if(ip_cmp(dst_ip,src_ip)>=0){
               hashing_struct.ips.u32[0] = ip_get_v4_as_int(dst_ip);
               hashing_struct.ips.u32[1] = ip_get_v4_as_int(src_ip);
              }else{
               hashing_struct.ips.u32[1] = ip_get_v4_as_int(dst_ip);
               hashing_struct.ips.u32[0] = ip_get_v4_as_int(src_ip);
              }

           } else {
              pair_ip_len = 4 * sizeof(uint64_t);
              if(ip_cmp(dst_ip,src_ip)>=0){
                memcpy(&(hashing_struct.ips.u64[0]), dst_ip, 2 * sizeof(uint64_t));
                memcpy(&(hashing_struct.ips.u64[2]), src_ip, 2 * sizeof(uint64_t));
              }else{
                memcpy(&(hashing_struct.ips.u64[2]), dst_ip, 2 * sizeof(uint64_t));
                memcpy(&(hashing_struct.ips.u64[0]), src_ip, 2 * sizeof(uint64_t));
              }
           }

           hash = crc32a((char *) &hashing_struct, sizeof(ports_t)+pair_ip_len);
           pair_ip_node = hash % nodes_num;

           ret = trap_send_data(pair_ip_node, data, data_size,TRAP_NO_WAIT);
            if (ret == TRAP_E_OK) {
               cnt_s++;
               continue;
            }
            TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, cnt_t++; continue, break)
         }
      } else {
         TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, cnt_t++; puts("trap_recv timeout"); continue, break)
      }
   }
 }



/**************************************************************************************************************************/


int main(int argc, char **argv)
{
   terminate = 0;

   double optimal;
   uint64_t total_flows;
   unsigned long stats_period = 0;
   uint8_t lines_distr = FALSE, hash_distr = FALSE, rand_distr = FALSE;
   char opt, *end_ptr = NULL;
   int x, flag_cnt = 0, y;
   nodes_num = 0;



   /* **** TRAP initialization **** */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {

      case 'N':
         nodes_num = strtoul(optarg, &end_ptr, 10);
         if (nodes_num == ULONG_MAX) {
            fprintf(stderr, "Error: invalid argument of 'N' parameter, expecting uint32.\n");
            goto fin_basic;
         }
         break;

      default:
         fprintf(stderr, "Invalid arguments.\n");
         goto fin_basic;
      }
   }

   if (nodes_num == 0 || nodes_num > 256) {
      fprintf(stderr, "Error: unspecified or wrong number of nodes (\"-N num\") in range <1,256>\n");
      goto fin_basic;
   }


   /************ SIGNAL HANDLING *************/



   // set output interfaces timeout to TRAP_WAIT (blocking mode)
   for (x = 0; x < 1 * nodes_num; x++) {
      trap_ifcctl(TRAPIFC_OUTPUT, x, TRAPCTL_SETTIMEOUT, OUT_IFC_TIMEOUT);
   }

   init_crc32c_table();

   traffic_repeater();


/* **** Cleanup **** */

fin_basic:
   ur_finalize();
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   exit(0);
}
