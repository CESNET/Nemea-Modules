/**
 * \file topn.c
 * \brief Topn module for computing various Top N statistics online.
 * \author Dominik Tran <xtrand00@stud.fit.vutbr.cz>
 * \author Jaroslav Hlavac <hlavaj20@fit.cvut.cz>
 * \date 2016
 * \date 2017
 */
/*
 * Copyright (C) 2016,2017 CESNET
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

#include "topn.h"
#include "fields.h"

UR_FIELDS(
   uint32 PACKETS,
   uint64 BYTES,
   ipaddr SRC_IP,
   ipaddr DST_IP,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 PROTOCOL
)

/* Structure with information about module */
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("topn", "Module for computing various Top N statistics.", 1, 0)

#define MODULE_PARAMS(PARAM) \
   PARAM('n', "top_n", "Number of entities for top N statistics.", required_argument, "uint8_t") \
   PARAM('l', "time", "Length of time interval in seconds. Statistics are calculated upon this interval.", required_argument, "uint8_t") \
   PARAM('p', "ports", "Specific ports upon which statistics will be calculated independently. Use format -p x1,x2,x3...", required_argument, "string") \
   PARAM('m', "prefix", "Length of the prefix for IPv4 and IPv6. Use format -m x1,x2 for both or -m x1 for IPv4 only.", required_argument, "string")

time_t time1;
static int print_stats = 0;
static int stop = 0;
static int interval = 0;
static int topn = 0;
static int *port = NULL;
static int port_cnt = 0;
static int port_set = -1;

/* Handling SIGTERM and SIGINT signals */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

int main(int argc, char **argv)
{
   int ret;

   int array_counter = 0;
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   /* TRAP initialization */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /* Register signal handler. */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   signal(SIGALRM, sig_handler);

   /* Create UniRec template */
   char *unirec_specifier = "PACKETS,BYTES,SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL";
   char opt;
   uint64_t prefix128[2] = {0, 0};
   uint32_t prefix = 0;
   int prefix_set = 0;
   int prefix_only_v4 = -1;

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'n':
         topn = atoi(optarg);
         if (topn == 0) {
            fprintf(stderr, "Invalid argument for parameter -n\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return EXIT_FAILURE;
         }
         break;

      case 'l':
         interval = atoi(optarg);
         if (interval == 0) {
            fprintf(stderr, "Invalid argument for parameter -l\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return EXIT_FAILURE;
         }
         break;

      case 'p':
         if (process_ports_args(optarg) == -1) {
            fprintf(stderr, "Error during processing -p parameter.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return EXIT_FAILURE;
         }
         break;

      case 'm':
         if (process_prefix_args(optarg, prefix128, &prefix, &prefix_set, &prefix_only_v4) == -1) {
            fprintf(stderr, "Error during processing -m parameter.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return EXIT_FAILURE;
         }
         break;

      default:
         fprintf(stderr, "Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return EXIT_FAILURE;
      }
   }

   if (topn == 0) {
      fprintf(stderr, "Parameter -n missing.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return EXIT_FAILURE;
   }

   if (interval == 0) {
      fprintf(stderr, "Parameter -l missing.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return EXIT_FAILURE;
   }

   ur_template_t *tmplt = ur_create_input_template(0, unirec_specifier, NULL);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return EXIT_FAILURE;
   }

   /* Counting Top N flows */
   flow_t *array_of_bytes = calloc(topn, sizeof(flow_t));
   flow_t **sorted_array_of_bytes = calloc(topn, sizeof(flow_t*));
   flow_t *record_bytes = calloc(1, sizeof(flow_t));
   flow_t *array_of_packets = calloc(topn, sizeof(flow_t));
   flow_t **sorted_array_of_packets = calloc(topn, sizeof(flow_t*));
   flow_t *record_packets = calloc(1, sizeof(flow_t));

   if (array_of_bytes == NULL || sorted_array_of_bytes == NULL || record_bytes == NULL || array_of_packets == NULL || sorted_array_of_packets == NULL || record_packets == NULL) {
      malloc_err();
   }

   flow_t **array_of_bytes_port = NULL;
   flow_t ***sorted_array_of_bytes_port = NULL;
   flow_t **array_of_packets_port = NULL;
   flow_t ***sorted_array_of_packets_port = NULL;
   int *array_counter_port = NULL;

   if (port_set != -1) {
      array_of_bytes_port = malloc(port_cnt *(sizeof(flow_t *)));
      sorted_array_of_bytes_port = malloc(port_cnt *(sizeof(flow_t **)));
      array_of_packets_port = malloc(port_cnt *(sizeof(flow_t *)));
      sorted_array_of_packets_port = malloc(port_cnt *(sizeof(flow_t **)));
      array_counter_port = malloc(port_cnt *(sizeof(int)));

      if (array_of_bytes_port == NULL || sorted_array_of_bytes_port == NULL || array_of_packets_port == NULL || sorted_array_of_packets_port == NULL || array_counter_port == NULL) {
         malloc_err();
      }

      for (int i = 0; i < port_cnt; i ++) {
         array_of_bytes_port[i] = malloc(topn * sizeof(flow_t));
         sorted_array_of_bytes_port[i] = malloc(topn * sizeof(flow_t*));
         array_of_packets_port[i] = malloc(topn * sizeof(flow_t));
         sorted_array_of_packets_port[i] = malloc(topn * sizeof(flow_t*));
         array_counter_port[i] = 0;

         if (array_of_bytes_port[i] == NULL || sorted_array_of_bytes_port[i] == NULL || array_of_packets_port[i] == NULL || sorted_array_of_packets_port[i] == NULL) {
            malloc_err();
         }
      }
   }

   /* Counting top N ports */

   port_t *array_of_ports = calloc(65536, sizeof(port_t));

   if (array_of_ports == NULL) {
      malloc_err();
   }

   port_t **array_of_ports_port = NULL;

   if (port_set != -1) {
      array_of_ports_port = malloc(port_cnt *(sizeof(port_t *)));

      if (array_of_ports_port == NULL) {
         malloc_err();
      }

      for (int i = 0; i < port_cnt; i++) {
         array_of_ports_port[i] = calloc(65536, sizeof(port_t));

         if (array_of_ports_port[i] == NULL) {
            malloc_err();
         }
      }
   }

   /* Top N IPs */
   fht_table_t *table_flows = fht_init(HASH_TABLE_SIZE * 4, sizeof(ip_addr_t), sizeof(ip_t), 0);      /* 32k */
   fht_iter_t *iter_flows = fht_init_iter(table_flows);
   fhf_table_t *table_pab = fhf_init(HASH_TABLE_SIZE, sizeof(ip_addr_t), sizeof(ip_t));      /* 8k, pab = packets and bytes */
   fhf_iter_t *iter_pab = fhf_init_iter(table_pab);

   if (table_flows == NULL || iter_flows == NULL || table_pab == NULL || iter_pab == NULL) {
      malloc_err();
   }

   fht_table_t **table_flows_port = NULL;
   fht_iter_t **iter_flows_port = NULL;
   fhf_table_t **table_pab_port = NULL;
   fhf_iter_t **iter_pab_port = NULL;

   if (port_set != -1) {
      table_pab_port = malloc(port_cnt *(sizeof(fhf_table_t *)));
      iter_pab_port = malloc(port_cnt *(sizeof(fhf_iter_t *)));
      table_flows_port = malloc(port_cnt *(sizeof(fht_table_t *)));
      iter_flows_port = malloc(port_cnt *(sizeof(fht_iter_t *)));

      if (table_pab_port == NULL || iter_pab_port == NULL || table_flows_port == NULL || iter_flows_port == NULL) {
         malloc_err();
      }

      for (int i = 0; i < port_cnt; i++) {
         table_pab_port[i] = fhf_init(HASH_TABLE_SIZE / 2, sizeof(ip_addr_t), sizeof(ip_t));   /* 4k */
         iter_pab_port[i] = fhf_init_iter(table_pab_port[i]);
         table_flows_port[i] = fht_init(HASH_TABLE_SIZE, sizeof(ip_addr_t), sizeof(ip_t), 0);   /* 8k */
         iter_flows_port[i] = fht_init_iter(table_flows_port[i]);

         if (table_pab_port[i] == NULL || iter_pab_port[i] == NULL || table_flows_port[i] == NULL || iter_flows_port[i] == NULL) {
            malloc_err();
         }

      }
   }

   /* Top networks */
   fht_table_t *table_prefix_flows = fht_init(HASH_TABLE_SIZE * 2, sizeof(ip_addr_t), sizeof(ip_t), 0);   /* 16k */
   fht_iter_t *iter_prefix_flows = fht_init_iter(table_prefix_flows);
   fhf_table_t *table_prefix_pab = fhf_init(HASH_TABLE_SIZE, sizeof(ip_addr_t), sizeof(ip_t));   /* 8k */
   fhf_iter_t *iter_prefix_pab = fhf_init_iter(table_prefix_pab);

   if (table_prefix_flows == NULL || iter_prefix_flows == NULL || table_prefix_pab == NULL || iter_prefix_pab == NULL) {
      malloc_err();
   }

   fht_table_t *table_prefix_flows_v6 = NULL;
   fht_iter_t *iter_prefix_flows_v6 = NULL;
   fhf_table_t *table_prefix_pab_v6 = NULL;
   fhf_iter_t *iter_prefix_pab_v6 = NULL;

   if (prefix_only_v4 == -1) {
      table_prefix_flows_v6 = fht_init(HASH_TABLE_SIZE * 2, sizeof(ip_addr_t), sizeof(ip_t), 0);   /* 16k */
      iter_prefix_flows_v6 = fht_init_iter(table_prefix_flows_v6);
      table_prefix_pab_v6 = fhf_init(HASH_TABLE_SIZE, sizeof(ip_addr_t), sizeof(ip_t));   /* 8k */
      iter_prefix_pab_v6 = fhf_init_iter(table_prefix_pab_v6);

      if (table_prefix_flows_v6 == NULL || iter_prefix_flows_v6 == NULL || table_prefix_pab_v6 == NULL || iter_prefix_pab_v6 == NULL) {
         malloc_err();
      }
   }

   fhf_table_t **table_prefix_pab_port = NULL;
   fhf_iter_t **iter_prefix_pab_port = NULL;

   fht_table_t **table_prefix_flows_port = NULL;
   fht_iter_t **iter_prefix_flows_port = NULL;

   fhf_table_t **table_prefix_pab_port_v6 = NULL;
   fhf_iter_t **iter_prefix_pab_port_v6 = NULL;

   fht_table_t **table_prefix_flows_port_v6 = NULL;
   fht_iter_t **iter_prefix_flows_port_v6 = NULL;

   if (port_set != -1) {
      table_prefix_pab_port = malloc(port_cnt *(sizeof(fhf_table_t *)));
      iter_prefix_pab_port = malloc(port_cnt *(sizeof(fhf_iter_t *)));
      table_prefix_flows_port = malloc(port_cnt *(sizeof(fht_table_t *)));
      iter_prefix_flows_port = malloc(port_cnt *(sizeof(fht_iter_t *)));

      if (table_prefix_pab_port == NULL || iter_prefix_pab_port == NULL || table_prefix_flows_port == NULL || iter_prefix_flows_port == NULL) {
         malloc_err();
      }

      if (prefix_only_v4 == -1) {
         table_prefix_pab_port_v6 = malloc(port_cnt *(sizeof(fhf_table_t *)));
         iter_prefix_pab_port_v6 = malloc(port_cnt *(sizeof(fhf_iter_t *)));
         table_prefix_flows_port_v6 = malloc(port_cnt *(sizeof(fht_table_t *)));
         iter_prefix_flows_port_v6 = malloc(port_cnt *(sizeof(fht_iter_t *)));

         if (table_prefix_pab_port_v6 == NULL || iter_prefix_pab_port_v6 == NULL || table_prefix_flows_port_v6 == NULL || iter_prefix_flows_port_v6 == NULL) {
            malloc_err();
         }
      }

      for (int i = 0; i < port_cnt; i++) {
         table_prefix_pab_port[i] = fhf_init(HASH_TABLE_SIZE / 2, sizeof(ip_addr_t), sizeof(ip_t));   /* 4k */
         iter_prefix_pab_port[i] = fhf_init_iter(table_prefix_pab_port[i]);
         table_prefix_flows_port[i] = fht_init(HASH_TABLE_SIZE, sizeof(ip_addr_t), sizeof(ip_t), 0);   /* 8k */
         iter_prefix_flows_port[i] = fht_init_iter(table_prefix_flows_port[i]);

         if (table_prefix_pab_port[i] == NULL || iter_prefix_pab_port[i] == NULL || table_prefix_flows_port[i] == NULL || iter_prefix_flows_port[i] == NULL) {
            malloc_err();
         }

         if (prefix_only_v4 == -1) {
            table_prefix_pab_port_v6[i] = fhf_init(HASH_TABLE_SIZE / 2, sizeof(ip_addr_t), sizeof(ip_t));   /* 4k */
            iter_prefix_pab_port_v6[i] = fhf_init_iter(table_prefix_pab_port_v6[i]);
            table_prefix_flows_port_v6[i] = fht_init(HASH_TABLE_SIZE, sizeof(ip_addr_t), sizeof(ip_t), 0);   /* 8k */
            iter_prefix_flows_port_v6[i] = fht_init_iter(table_prefix_flows_port_v6[i]);

            if (table_prefix_pab_port_v6[i] == NULL || iter_prefix_pab_port_v6[i] == NULL || table_prefix_flows_port_v6[i] == NULL || iter_prefix_flows_port_v6[i] == NULL) {
               malloc_err();
            }
         }
      }
   }

   /* Additional code */
   ip_addr_t masked_ip;
   char *ip_string = malloc(INET6_ADDRSTRLEN);
   char *ip_string2 = malloc(INET6_ADDRSTRLEN);
   ip_t *record_ip = malloc(sizeof(ip_t));
   ip_addr_t *key_lost = malloc(sizeof(ip_addr_t));
   ip_t *data_lost = malloc(sizeof(ip_t));

   if (ip_string == NULL || ip_string2 == NULL || record_ip == NULL || key_lost == NULL || data_lost == NULL) {
      malloc_err();
   }

   uint64_t received_flows = 0;
   uint64_t all_bytes = 0;
   uint32_t average_bytes = 0;
   uint64_t all_packets = 0;
   uint32_t average_packets = 0;

   char time_print_buff[128];
   time_t time_print;

   const void *data;
   uint16_t data_size;

   seedMT(time(NULL));
   time1 = time(NULL);
   alarm(interval);

   while (!stop) {
      /* Receive data from input interface (block until data are available) */
      ret = TRAP_RECEIVE(0, data, data_size, tmplt);

      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      /* Check for end-of-stream message */
      if (data_size <= 1) {
         break;
      }

      received_flows++;
      all_bytes += ur_get(tmplt, data, F_BYTES);
      average_bytes = all_bytes / received_flows;
      all_packets += ur_get(tmplt, data, F_PACKETS);
      average_packets = all_packets / received_flows;

      /*if ((received_flows > 190000) && received_flows % 200000 == 0) {
         printf("%" PRIu64 "k (%" PRIu64 "M): average bytes: %d, average packets: %d,\n", received_flows / 1000, received_flows / 1000000, average_bytes, average_packets);
      }*/

      record_ip->bytes = ur_get(tmplt, data, F_BYTES);
      record_ip->packets = ur_get(tmplt, data, F_PACKETS);
      record_ip->flows = 1;
      record_ip->src_ip = ur_get(tmplt, data, F_SRC_IP);

      record_bytes->max_number = ur_get(tmplt, data, F_BYTES);
      record_bytes->src_ip = ur_get(tmplt, data, F_SRC_IP);
      record_bytes->dst_ip = ur_get(tmplt, data, F_DST_IP);
      record_bytes->src_port = ur_get(tmplt, data, F_SRC_PORT);
      record_bytes->dst_port = ur_get(tmplt, data, F_DST_PORT);
      record_bytes->protocol = ur_get(tmplt, data, F_PROTOCOL);

      record_packets->max_number = ur_get(tmplt, data, F_PACKETS);
      record_packets->src_ip = ur_get(tmplt, data, F_SRC_IP);
      record_packets->dst_ip = ur_get(tmplt, data, F_DST_IP);
      record_packets->src_port = ur_get(tmplt, data, F_SRC_PORT);
      record_packets->dst_port = ur_get(tmplt, data, F_DST_PORT);
      record_packets->protocol = ur_get(tmplt, data, F_PROTOCOL);


      /* Prefixes */

      if (prefix_set == 1) {
         if (ip_is4(&ur_get(tmplt, data, F_SRC_IP)) == 1) {
            masked_ip = ur_get(tmplt, data, F_SRC_IP);
            masked_ip.ui32[2] = masked_ip.ui32[2] & prefix;

            process_ip_flows(table_prefix_flows, &masked_ip, record_ip, key_lost, data_lost, data, tmplt);
            process_ip_pab(table_prefix_pab, &masked_ip, record_ip, data, tmplt,  average_packets,  average_bytes);

            if (port_set != -1) {
               for (int p = 0; p < port_cnt; p++) {
                  if (record_bytes->dst_port == port[p] || record_bytes->src_port == port[p]) {
                     process_ip_flows(table_prefix_flows_port[p], &masked_ip, record_ip, key_lost, data_lost, data, tmplt);
                     process_ip_pab(table_prefix_pab_port[p], &masked_ip, record_ip, data, tmplt,  average_packets / 3,  average_bytes / 3);
                  }
               }
            }
         } else if (prefix_only_v4 == -1) {
            masked_ip = (ur_get(tmplt, data, F_SRC_IP));
            masked_ip.ui64[0] = masked_ip.ui64[0] & prefix128[0];
            masked_ip.ui64[1] = masked_ip.ui64[1] & prefix128[1];

            process_ip_flows(table_prefix_flows_v6, &masked_ip, record_ip, key_lost, data_lost, data, tmplt);
            process_ip_pab(table_prefix_pab_v6, &masked_ip, record_ip, data, tmplt,  average_packets,  average_bytes);

            if (port_set != -1) {
               for (int p = 0; p < port_cnt; p++) {
                  if (record_bytes->dst_port == port[p] || record_bytes->src_port == port[p]) {
                     process_ip_flows(table_prefix_flows_port_v6[p], &masked_ip, record_ip, key_lost, data_lost, data, tmplt);
                     process_ip_pab(table_prefix_pab_port_v6[p], &masked_ip, record_ip, data, tmplt,  average_packets / 3,  average_bytes / 3);

                  }
               }
            }
         }
      }

      /* IPs */
      process_ip_flows(table_flows, &ur_get(tmplt, data, F_SRC_IP), record_ip, key_lost, data_lost, data, tmplt);
      process_ip_pab(table_pab, &ur_get(tmplt, data, F_SRC_IP), record_ip, data, tmplt,  average_packets,  average_bytes);

      if (port_set != -1) {
         for (int p = 0; p < port_cnt; p++) {
            if (record_bytes->dst_port == port[p] || record_bytes->src_port == port[p]) {
               process_ip_flows(table_flows_port[p], &ur_get(tmplt, data, F_SRC_IP), record_ip, key_lost, data_lost, data, tmplt);
               process_ip_pab(table_pab_port[p], &ur_get(tmplt, data, F_SRC_IP), record_ip, data, tmplt,  average_packets / 3,  average_bytes / 3);
            }
         }
      }

      /* Flows */
      process_flows(array_of_bytes,  sorted_array_of_bytes, record_bytes, array_counter);
      process_flows(array_of_packets, sorted_array_of_packets, record_packets, array_counter);
      if (array_counter < topn) {
         array_counter++;
      }

      if (port_set != -1) {
         for (int p = 0; p < port_cnt; p++) {
            if (record_bytes->dst_port == port[p] || record_bytes->src_port == port[p]) {
               process_flows(array_of_bytes_port[p], sorted_array_of_bytes_port[p], record_bytes, array_counter_port[p]);
               process_flows(array_of_packets_port[p], sorted_array_of_packets_port[p], record_packets, array_counter_port[p]);
               if (array_counter_port[p] < topn) {
                  array_counter_port[p]++;
               }
            }
         }
      }

      /* Ports */
      array_of_ports[ur_get(tmplt, data, F_DST_PORT)].flows += 1;
      array_of_ports[ur_get(tmplt, data, F_SRC_PORT)].flows += 1;
      array_of_ports[ur_get(tmplt, data, F_DST_PORT)].port = ur_get(tmplt, data, F_DST_PORT);
      array_of_ports[ur_get(tmplt, data, F_SRC_PORT)].port = ur_get(tmplt, data, F_SRC_PORT);

      array_of_ports[ur_get(tmplt, data, F_DST_PORT)].packets += ur_get(tmplt, data, F_PACKETS);
      array_of_ports[ur_get(tmplt, data, F_SRC_PORT)].packets += ur_get(tmplt, data, F_PACKETS);
      array_of_ports[ur_get(tmplt, data, F_DST_PORT)].bytes += ur_get(tmplt, data, F_BYTES);
      array_of_ports[ur_get(tmplt, data, F_SRC_PORT)].bytes += ur_get(tmplt, data, F_BYTES);


      if (port_set != -1) {
         for (int p = 0; p < port_cnt; p++) {
            if (record_bytes->dst_port == port[p]) {
               array_of_ports_port[p][ur_get(tmplt, data, F_SRC_PORT)].flows += 1;
               array_of_ports_port[p][ur_get(tmplt, data, F_SRC_PORT)].port = ur_get(tmplt, data, F_SRC_PORT);

               array_of_ports_port[p][ur_get(tmplt, data, F_SRC_PORT)].packets += ur_get(tmplt, data, F_PACKETS);
               array_of_ports_port[p][ur_get(tmplt, data, F_SRC_PORT)].bytes += ur_get(tmplt, data, F_BYTES);
            }

            if (record_bytes->src_port == port[p]) {
               array_of_ports_port[p][ur_get(tmplt, data, F_DST_PORT)].flows += 1;
               array_of_ports_port[p][ur_get(tmplt, data, F_DST_PORT)].port = ur_get(tmplt, data, F_DST_PORT);

               array_of_ports_port[p][ur_get(tmplt, data, F_DST_PORT)].packets += ur_get(tmplt, data, F_PACKETS);
               array_of_ports_port[p][ur_get(tmplt, data, F_DST_PORT)].bytes += ur_get(tmplt, data, F_BYTES);
            }
         }
      }

      /* Printing results after time is up */
      if (print_stats == 1) {
         time_print = time(NULL);
         strftime(time_print_buff, 128, "%Y-%m-%d %H:%M:%S", localtime (&time_print));
         printf ("\n===================\n%s\n===================\n", time_print_buff);

         print_top_flows(sorted_array_of_bytes, sorted_array_of_packets, array_counter, ip_string, ip_string2, -1);
         array_counter = 0;

         if (port_set != -1) {
            for (int p = 0; p < port_cnt; p++) {
               print_top_flows(sorted_array_of_bytes_port[p], sorted_array_of_packets_port[p], array_counter_port[p], ip_string, ip_string2, port[p]);
               array_counter_port[p] = 0;
            }
         }

         print_top_ports(array_of_ports, -1);
         memset(array_of_ports, 0, sizeof(port_t) * 65536);

         if (port_set != -1) {
            for (int p = 0; p < port_cnt; p++) {
               print_top_ports(array_of_ports_port[p], port[p]);
               memset(array_of_ports_port[p], 0, sizeof(port_t) * 65536);
            }
         }

         print_top_ip(ip_string, table_pab, iter_pab, table_flows, iter_flows, -1, 0);
         fhf_clear(table_pab);
         fhf_reinit_iter(iter_pab);
         fht_clear(table_flows);
         fht_reinit_iter(iter_flows);

         if (port_set != -1) {
            for (int p = 0; p < port_cnt; p++) {
               print_top_ip(ip_string, table_pab_port[p], iter_pab_port[p], table_flows_port[p], iter_flows_port[p], port[p], 0);
               fhf_clear(table_pab_port[p]);
               fhf_reinit_iter(iter_pab_port[p]);
               fht_clear(table_flows_port[p]);
               fht_reinit_iter(iter_flows_port[p]);
            }
         }

         if (prefix_set == 1) {
            print_top_ip(ip_string, table_prefix_pab, iter_prefix_pab, table_prefix_flows, iter_prefix_flows, -1, 1);
            fhf_clear(table_prefix_pab);
            fhf_reinit_iter(iter_prefix_pab);
            fht_clear(table_prefix_flows);
            fht_reinit_iter(iter_prefix_flows);

            if (port_set != -1) {
               for (int p = 0; p < port_cnt; p++) {
                  print_top_ip(ip_string, table_prefix_pab_port[p], iter_prefix_pab_port[p], table_prefix_flows_port[p], iter_prefix_flows_port[p], port[p], 1);
                  fhf_clear(table_prefix_pab_port[p]);
                  fhf_reinit_iter(iter_prefix_pab_port[p]);
                  fht_clear(table_prefix_flows_port[p]);
                  fht_reinit_iter(iter_prefix_flows_port[p]);
               }
            }

            if (prefix_only_v4 == -1) {
               print_top_ip(ip_string, table_prefix_pab_v6, iter_prefix_pab_v6, table_prefix_flows_v6, iter_prefix_flows_v6, -1, 1);
               fhf_clear(table_prefix_pab_v6);
               fhf_reinit_iter(iter_prefix_pab_v6);
               fht_clear(table_prefix_flows_v6);
               fht_reinit_iter(iter_prefix_flows_v6);

               if (port_set != -1) {
                  for (int p = 0; p < port_cnt; p++) {
                     print_top_ip(ip_string, table_prefix_pab_port_v6[p], iter_prefix_pab_port_v6[p], table_prefix_flows_port_v6[p], iter_prefix_flows_port_v6[p], port[p], 1);
                     fhf_clear(table_prefix_pab_port_v6[p]);
                     fhf_reinit_iter(iter_prefix_pab_port_v6[p]);
                     fht_clear(table_prefix_flows_port_v6[p]);
                     fht_reinit_iter(iter_prefix_flows_port_v6[p]);
                  }
               }
            }
         }

         print_stats = 0;

         received_flows = 0;
         all_bytes = 0;
         average_bytes = 0;
         all_packets = 0;
         average_packets = 0;

         alarm(interval);

         seedMT(time(NULL));
         time1 = time(NULL);
      }
   }

   /* Printing final results after interrupt */

   time_print = time(NULL);
   strftime (time_print_buff, 128, "%Y-%m-%d %H:%M:%S", localtime (&time_print));
   printf ("\n===================\n%s\n===================\n", time_print_buff);

   print_top_flows(sorted_array_of_bytes, sorted_array_of_packets, array_counter, ip_string, ip_string2, -1);

   if (port_set != -1) {
      for (int p = 0; p < port_cnt; p++) {
         print_top_flows(sorted_array_of_bytes_port[p], sorted_array_of_packets_port[p], array_counter_port[p], ip_string, ip_string2, port[p]);
      }
   }

   print_top_ports(array_of_ports, -1);

   if (port_set != -1) {
      for (int p = 0; p < port_cnt; p++) {
         print_top_ports(array_of_ports_port[p], port[p]);
      }
   }

   print_top_ip(ip_string, table_pab, iter_pab, table_flows, iter_flows, -1, 0);

   if (port_set != -1) {
      for (int p = 0; p < port_cnt; p++) {
         print_top_ip(ip_string, table_pab_port[p], iter_pab_port[p], table_flows_port[p], iter_flows_port[p], port[p], 0);
      }
   }

   if (prefix_set == 1) {
      print_top_ip(ip_string, table_prefix_pab, iter_prefix_pab, table_prefix_flows, iter_prefix_flows,-1, 1);

      if (port_set != -1) {
         for (int p = 0; p < port_cnt; p++) {
            print_top_ip(ip_string, table_prefix_pab_port[p], iter_prefix_pab_port[p], table_prefix_flows_port[p], iter_prefix_flows_port[p], port[p], 1);
         }
      }

      if (prefix_only_v4 == -1) {
         print_top_ip(ip_string, table_prefix_pab_v6, iter_prefix_pab_v6, table_prefix_flows_v6, iter_prefix_flows_v6, -1, 1);

         if (port_set != -1) {
            for (int p = 0; p < port_cnt; p++) {
               print_top_ip(ip_string, table_prefix_pab_port_v6[p], iter_prefix_pab_port_v6[p], table_prefix_flows_port_v6[p], iter_prefix_flows_port_v6[p], port[p], 1);
            }
         }
      }
   }


   /* Cleanup */
   /* Alarm has to be cancelled before cleanup */
   alarm(0);

   free(ip_string2);
   free(ip_string);

   if (port_set != -1) {
      for (int i = 0; i < port_cnt; i++) {
         free(sorted_array_of_bytes_port[i]);
         free(array_of_bytes_port[i]);
         free(sorted_array_of_packets_port[i]);
         free(array_of_packets_port[i]);
      }

      free(array_of_bytes_port);
      free(sorted_array_of_bytes_port);
      free(array_of_packets_port);
      free(sorted_array_of_packets_port);

      free(array_counter_port);

      free(port);
   }

   free(record_bytes);
   free(sorted_array_of_bytes);
   free(array_of_bytes);
   free(record_packets);
   free(sorted_array_of_packets);
   free(array_of_packets);


   free(array_of_ports);

   if (port_set != -1) {
      for (int i = 0; i < port_cnt; i++) {
         free(array_of_ports_port[i]);
      }
      free(array_of_ports_port);
   }

   free(record_ip);


   fhf_destroy(table_pab);
   fhf_destroy_iter(iter_pab);

   fht_destroy(table_flows);
   fht_destroy_iter(iter_flows);

   if (port_set != -1)  {
      for (int i = 0; i < port_cnt; i++) {
         fhf_destroy(table_pab_port[i]);
         fhf_destroy_iter(iter_pab_port[i]);

         fht_destroy(table_flows_port[i]);
         fht_destroy_iter(iter_flows_port[i]);
      }

      free(table_pab_port);
      free(iter_pab_port);

      free(table_flows_port);
      free(iter_flows_port);
   }

   free(key_lost);
   free(data_lost);

   if (prefix_set == 1) {
      fht_destroy(table_prefix_flows);
      fht_destroy_iter(iter_prefix_flows);

      fhf_destroy(table_prefix_pab);
      fhf_destroy_iter(iter_prefix_pab);

      if (prefix_only_v4 == -1) {
         fht_destroy(table_prefix_flows_v6);
         fht_destroy_iter(iter_prefix_flows_v6);

         fhf_destroy(table_prefix_pab_v6);
         fhf_destroy_iter(iter_prefix_pab_v6);
      }

      if (port_set != -1) {
         for (int i = 0; i < port_cnt; i++) {
            fhf_destroy(table_prefix_pab_port[i]);
            fhf_destroy_iter(iter_prefix_pab_port[i]);

            fht_destroy(table_prefix_flows_port[i]);
            fht_destroy_iter(iter_prefix_flows_port[i]);

            if (prefix_only_v4 == -1) {
               fhf_destroy(table_prefix_pab_port_v6[i]);
               fhf_destroy_iter(iter_prefix_pab_port_v6[i]);

               fht_destroy(table_prefix_flows_port_v6[i]);
               fht_destroy_iter(iter_prefix_flows_port_v6[i]);
            }
         }

         free(table_prefix_pab_port);
         free(iter_prefix_pab_port);

         free(table_prefix_flows_port);
         free(iter_prefix_flows_port);

         if (prefix_only_v4 == -1) {
            free(table_prefix_pab_port_v6);
            free(iter_prefix_pab_port_v6);

            free(table_prefix_flows_port_v6);
            free(iter_prefix_flows_port_v6);
         }
      }
   }

   /* Trap cleanup before exiting */
   TRAP_DEFAULT_FINALIZATION();

   ur_finalize();
   ur_free_template(tmplt);
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return EXIT_SUCCESS;
}

void sig_handler(int signal)
{
   if (signal != SIGALRM) {
      return;
   }
   print_stats = 1;
}

int get_array_index(uint32_t key, flow_t **sorted_array, size_t num) {
   if (sorted_array[0]->max_number > key) {
      return -1;
   }

   /**
   * In case sorted_array has less than 4 elements, I process it manually.
   * It's because main algorithm (see below) doesn't work well for 1, 2 and 3 members.
   */

   if (num == 1) {
      if (sorted_array[0]->max_number > key) {
         return -1;
      } else {
         return 0;
      }
   }

   if (num == 2) {
      if (sorted_array[0]->max_number > key) {
         return -1;
      } else if (sorted_array[0]->max_number < key) {
         if (sorted_array[1]->max_number > key) {
            return 0;
         } else if (sorted_array[1]->max_number == key) {
            return 0;
         } else {
            return 1;
         }
      }
   }

   if (num == 3) {
      if (sorted_array[0]->max_number > key) {
         return -1;
      } else if (sorted_array[0]->max_number < key) {
         if (sorted_array[1]->max_number > key) {
            return 0;
         } else if (sorted_array[1]->max_number == key) {
            return 0;
         } else {
            if (sorted_array[2]->max_number > key) {
               return 1;
            } else if (sorted_array[2]->max_number == key) {
               return 1;
            } else {
               return 2;
            }
         }
      }
   }

   int first = 0;
   int last = num -1;
   int middle = (first + last) / 2;

   while (first <= last) {
      if (sorted_array[middle]->max_number < key) {
         first = middle + 1;
      } else if (sorted_array[middle]->max_number == key) {
         while (sorted_array[middle]->max_number == key) {
            if (middle == 0) {
               return -1;
            }
            middle--;
         }
         return middle;
      } else {
         last = middle - 1;
      }

      middle = (first + last) / 2;
   }

   if (first > last) {
      if (last == -1) {
         return -1;
      } else if (first -1 != -1) {
         return first -1;
      }
   }
   return -1;
}

void process_flows(flow_t *array, flow_t **sorted_array, flow_t *record, int array_counter)
{
   int array_index;

   if (array_counter == 0) {
      sorted_array[0] = memmove(&array[0], record, sizeof(flow_t));
   } else if (array_counter < topn) {
      array_index = get_array_index (record->max_number, sorted_array, array_counter);

      if (array_counter == 1) {
         if (array_index == -1) {
            sorted_array[1] = sorted_array[0];
            sorted_array[0] = memmove(&array[1], record, sizeof(flow_t));
         } else {
            sorted_array[1] = memmove(&array[1], record, sizeof(flow_t));
         }
      } else {
         if (array_index == -1) {
            for (int i = array_counter; i > 0; i--) {
               sorted_array[i] = sorted_array[i-1];
            }

            sorted_array[0] = memmove(&array[array_counter], record, sizeof(flow_t));
         } else if (array_index != -1) {
            for (int i = array_counter; i > array_index + 1; i--) {
               sorted_array[i] = sorted_array[i-1];
            }

            sorted_array[array_index + 1] = memmove(&array[array_counter], record, sizeof(flow_t));

         }
      }
   } else if (array_counter == topn) {
      array_index = get_array_index (record->max_number, sorted_array, array_counter);

      if (array_index != -1) {
         flow_t *temp = sorted_array[0];

         for (int i = 0; i < array_index; i++) {
            sorted_array[i] = sorted_array[i + 1];
         }

         sorted_array[array_index] = memmove(temp, record, sizeof(flow_t));
      }
   }
}

void print_top_flows(flow_t **sorted_array_of_bytes, flow_t **sorted_array_of_packets, int array_counter, char *ip_string, char *ip_string2, int port_number)
{
   printf("\n");
   if (port_number == -1) {
      printf("Top flows based on transferred bytes\n");
   } else {
      printf("Top flows based on transferred bytes by port %d\n", port_number);
   }
   printf("------------------------------------\n");
   printf("N | Src ip | Dst ip | Src port | Dst port | Protocol | Bytes\n");

   int y = 0;
   for (int i = array_counter-1; i >= 0; y++, i--) {
      ip_to_str(&sorted_array_of_bytes[i]->src_ip, ip_string);
      ip_to_str(&sorted_array_of_bytes[i]->dst_ip, ip_string2);

      printf("%d\t%s\t%s\t%d\t%d\t%d\t%u\n", y + 1, ip_string, ip_string2,
      sorted_array_of_bytes[i]->src_port, sorted_array_of_bytes[i]->dst_port, sorted_array_of_bytes[i]->protocol,sorted_array_of_bytes[i]->max_number);
   }

   printf("\n");
   if (port_number == -1) {
      printf("Top flows based on transferred packets\n");
   } else {
      printf("Top flows based on transferred packets by port %d\n", port_number);
   }
   printf("------------------------------------\n");
   printf("N | Src ip | Dst ip | Src port | Dst port | Protocol | Packets\n");

   y=0;
   for (int i = array_counter-1; i >= 0; y++, i--) {
      ip_to_str(&sorted_array_of_packets[i]->src_ip, ip_string);
      ip_to_str(&sorted_array_of_packets[i]->dst_ip, ip_string2);

      printf("%d\t%s\t%s\t%d\t%d\t%d\t%u\n", y + 1, ip_string, ip_string2,
      sorted_array_of_packets[i]->src_port, sorted_array_of_packets[i]->dst_port, sorted_array_of_packets[i]->protocol, sorted_array_of_packets[i]->max_number);
   }
}

void print_top_ports(port_t *array_of_ports, int port_number)
{
   qsort (array_of_ports, 65536, sizeof(port_t), compare_flows);
   printf("\n");
   if (port_number == -1) {
      printf("Top ports based on transferred flows\n");
   } else {
      printf("Top ports based on transferred flows who communicated the most with port %d\n", port_number);
   }
   printf("------------------------------------\n");
   printf("N\tPort\tFlows\n");

   for (int i = 0; i < topn; i++) {
      if (array_of_ports[i].flows == 0) {
         break;
      }
      printf("%d\t%u\t%" PRIu64 "\n", i + 1, array_of_ports[i].port, array_of_ports[i].flows);
   }

   qsort (array_of_ports, 65536, sizeof(port_t), compare_packets);
   printf("\n");
   if (port_number == -1) {
      printf("Top ports based on transferred packets\n");
   } else {
      printf("Top ports based on transferred packets who communicated the most with port %d\n", port_number);
   }
   printf("------------------------------------\n");
   printf("N\tPort\tPackets\n");

   for (int i = 0; i < topn; i++) {
      if (array_of_ports[i].packets == 0) {
         break;
      }
      printf("%d\t%u\t%" PRIu64 "\n", i + 1, array_of_ports[i].port, array_of_ports[i].packets);
   }

   qsort (array_of_ports, 65536, sizeof(port_t), compare_bytes);
   printf("\n");
   if (port_number == -1) {
      printf("Top ports based on transferred bytes\n");
   } else {
      printf("Top ports based on transferred bytes who communicated the most with port %d\n", port_number);
   }
   printf("------------------------------------\n");
   printf("N\tPort\tBytes\n");

   for (int i = 0; i < topn; i++) {
      if (array_of_ports[i].bytes == 0) {
         break;
      }
      printf("%d\t%u\t%" PRIu64 "\n", i + 1, array_of_ports[i].port, array_of_ports[i].bytes);
   }
}

void print_top_ip(char *ip_string, fhf_table_t *table_pab, fhf_iter_t *iter_pab, fht_table_t *table_flows, fht_iter_t *iter_flows, int port_number, int prefix_set)
{
   ip_t *ip_array = (void *) &(table_flows->data_field[0]);
   int number_of_records = 0;

   /* Flows */
   while (fht_get_next_iter(iter_flows) != FHF_ITER_RET_END) {
      ip_t *entry = (void *) &iter_flows->data_ptr[0];
      ip_addr_t *address = (void *) &iter_flows->key_ptr[0];

      ip_array[number_of_records].flows = entry->flows;
      ip_array[number_of_records].packets = entry->packets;
      ip_array[number_of_records].bytes = entry->bytes;
      ip_array[number_of_records].src_ip = address[0];

      number_of_records++;
   }

   if (number_of_records == 0) {
      return;
   }

   qsort (ip_array, number_of_records, sizeof(ip_t), compare_flows_table);
   printf("\n");
   if (prefix_set == 0) {
      if (port_number == -1) {
         printf("Top IPs based on transferred flows\n");
      } else {
         printf("Top IPs based on transferred flows by port %d\n", port_number);
      }
   } else {
      if (port_number == -1) {
         printf("Top networks based on transferred flows\n");
      } else {
         printf("Top networks based on transferred flows by port %d\n", port_number);
      }
   }
   printf("------------------------------------\n");
   printf("N\tIP\t\tFlows\n");

   for (int i = 0; i < topn && i < number_of_records; i++) {
      ip_to_str(&ip_array[i].src_ip, ip_string);
      printf("%d\t%s\t%" PRIu64 "\n", i + 1, ip_string, ip_array[i].flows);
   }


   /* Packets */
   ip_array = (void *) &(table_pab->data_field[0]);
   number_of_records = 0;

   while (fhf_get_next_iter(iter_pab) != FHF_ITER_RET_END) {
      ip_t *entry = (ip_t *) &iter_pab->data_ptr[0];
      ip_addr_t *address = (ip_addr_t *) &iter_pab->key_ptr[0];

      ip_array[number_of_records].flows = entry->flows;
      ip_array[number_of_records].packets = entry->packets;
      ip_array[number_of_records].bytes = entry->bytes;
      ip_array[number_of_records].src_ip = address[0];

      number_of_records++;
   }

   qsort (ip_array, number_of_records, sizeof(ip_t), compare_packets_table);
   printf("\n");
   if (prefix_set == 0) {
      if (port_number == -1) {
         printf("Top IPs based on transferred packets\n");
      } else {
         printf("Top IPs based on transferred packets by port %d\n", port_number);
      }
   } else {
      if (port_number == -1) {
         printf("Top networks based on transferred packets\n");
      } else {
         printf("Top networks based on transferred packets by port %d\n", port_number);
      }
   }
   printf("------------------------------------\n");
   printf("N\tIP\t\tPackets\n");

   for (int i = 0; i < topn && i < number_of_records; i++) {
      ip_to_str(&ip_array[i].src_ip, ip_string);
      printf("%d\t%s\t%" PRIu64 "\n", i + 1, ip_string, ip_array[i].packets);
   }


   /* Bytes */
   qsort (ip_array, number_of_records, sizeof(ip_t), compare_bytes_table);
   printf("\n");
   if (prefix_set == 0) {
      if (port_number == -1) {
         printf("Top IPs based on transferred bytes\n");
      } else {
         printf("Top IPs based on transferred bytes by port %d\n", port_number);
      }
   } else {
      if (port_number == -1) {
         printf("Top networks based on transferred bytes\n");
      } else {
         printf("Top networks based on transferred bytes by port %d\n", port_number);
      }
   }
   printf("------------------------------------\n");
   printf("N\tIP\t\tBytes\n");

   for (int i = 0; i < topn && i < number_of_records; i++) {
      ip_to_str(&ip_array[i].src_ip, ip_string);
      printf("%d\t%s\t%" PRIu64 "\n", i + 1, ip_string, ip_array[i].bytes);
   }
}

int process_prefix_args(char *optarg, uint64_t *prefix128, uint32_t *prefix, int *prefix_set, int *prefix_only_v4)
{
   char *comma;
   comma = strchr(optarg, ',');
   if (comma != NULL && ((optarg-comma) < 3)) {
      *prefix_only_v4 = -1;

      if (strchr(comma + 1, ',') != NULL) {
         return -1;
      }
   } else if (comma == NULL && strlen(optarg) < 3) {
      *prefix_only_v4 = 1;
   } else {
      return -1;
   }

   int length;
   length = atoi(optarg);

   if (length == 0 || length > 32) {
      return -1;
   }

   uint32_t mask = 1;
   for (int i = 0; i < length; i++) {
      mask = mask * 2;
   }
   *prefix = mask -1;


   if (*prefix_only_v4 == -1) {
      length = atoi(comma + 1);
      if (length == 0 || length > 128) {
         return -1;
      }

      uint64_t mask64 = 1;
      for (int i = 0; i < length && i < 64; i++) {
         mask64 = mask64 * 2;
      }
      prefix128[0] = mask64 -1;

      if (length > 64) {
         mask64 = 1;
         for (int i = 0; i < (length - 64); i++) {
            mask64 = mask64 * 2;
         }
         prefix128[1] = mask64 -1;
      }
   }

   *prefix_set = 1;

   return 0;
}

int process_ports_args(char *optarg) {
   char *token;
   char *end;

   token = strchr(optarg, ',');

   while (token!=NULL) {
      port_cnt++;
      token = strchr(token + 1, ',');
   }

   port = malloc((port_cnt + 1) * (sizeof(int)));

   if (port == NULL) {
      return -1;
   }

   port_cnt = 0;

   token = strtok(optarg, ",");

   while (token!=NULL) {
      if (strlen(token) > 5) {
         return -1;
      }

      port[port_cnt] = strtol(token, &end, 10);

      if (port[port_cnt] == 0 && end == token) {
         return -1;
      }

      port_cnt++;
      token = strtok(NULL, ",");
   }

   port_set = 0;

   return 0;
}


void process_ip_flows(fht_table_t *table_flows, ip_addr_t *ip, ip_t *record, ip_addr_t *key_lost, ip_t *data_lost, const void *data, ur_template_t *tmplt)
{
   ip_t *record2 = NULL;
   uint64_t table_row;
   uint64_t table_col_row;
   int ret;
   int removed = 0;

   int random = randomMT() % FLOWS_RANDOM_MAX;

   if ((record2 = fht_get_data(table_flows, ip)) == NULL) {
      if (random < FLOWS_RANDOM) {
         ret = fht_insert(table_flows, ip, record, key_lost, data_lost);

         if (ret == FHT_INSERT_LOST) {
            table_row = (table_flows->table_rows - 1) & (table_flows->hash_function)(ip, table_flows->key_size);
            table_col_row = table_row *FHT_TABLE_COLS;

            int timediff = (int) difftime(time(NULL), time1);
            timediff = (timediff / FLOWS_TIME_INTERVAL) + 1;

            for (int i = 0; i < FHT_TABLE_COLS; i++) {
               if (((ip_t *) &(table_flows->data_field[(table_col_row + i) * table_flows->data_size]))->flows < FLOWS_MULTIPLIER * timediff && (ip_cmp(ip, ((ip_addr_t*) &(table_flows->key_field[(table_col_row + i) * table_flows->key_size]))) != 0)) {
                  fht_remove(table_flows, ((ip_addr_t*) &(table_flows->key_field[(table_col_row + i) * table_flows->key_size])));
                  removed = 1;
               }
            }

            if (removed == 1) {
               if (data_lost->flows >= FLOWS_BIG_BASE + timediff * FLOWS_BIG_MULTIPLIER) {
                  fht_insert(table_flows, &data_lost->src_ip, data_lost, key_lost, data_lost);
               }
            }
         }
      }
   } else {
      record2->bytes += ur_get(tmplt, data, F_BYTES);
      record2->packets += ur_get(tmplt, data, F_PACKETS);
      record2->flows += 1;
   }
}

void process_ip_pab(fhf_table_t *table_pab, ip_addr_t *ip, ip_t *record, const void *data, ur_template_t *tmplt, int average_packets, int average_bytes)
{
   ip_t *record2 = NULL;
   uint64_t table_row;
   uint64_t table_col_row;
   int ret;
   int removed = 0;

   if (fhf_get_data(table_pab, ip, (void *) &record2) == FHF_FOUND) {
      record2->bytes += ur_get(tmplt, data, F_BYTES);
      record2->packets += ur_get(tmplt, data, F_PACKETS);
      record2->flows += 1;
   } else {
      ret = fhf_insert(table_pab, ip, record);

      if (ret == FHF_INSERT_FULL) {
         table_row = (table_pab->table_rows - 1) & (table_pab->hash_function)(ip, table_pab->key_size, (uint64_t) table_pab);
         table_col_row = table_row *FHF_TABLE_COLS;

         int timediff = (int) difftime(time(NULL), time1);
         timediff = (timediff / PAB_TIME_INTERVAL) + 1;

         for (int i = 0; i < FHF_TABLE_COLS; i++) {
            if (((ip_t *) &(table_pab->data_field[(table_col_row + i) *table_pab->data_size]))->packets < average_packets * (PAB_BASE + timediff * PAB_MULTIPLIER) &&
            ((ip_t *) &(table_pab->data_field[(table_col_row + i) * table_pab->data_size]))->bytes < average_bytes * (PAB_BASE + timediff * PAB_MULTIPLIER)) {
               fhf_remove(table_pab, ((ip_addr_t*) (&(table_pab->key_field[(table_col_row + i) * table_pab->key_size]))));
               removed = 1;
            }
         }

         if (removed == 1) {
            if (ur_get(tmplt, data, F_PACKETS) > average_packets * PAB_BASE || ur_get(tmplt, data, F_BYTES) > average_bytes * (PAB_BASE * 2)) {
               fhf_insert(table_pab, ip, record);
            }
         }
      }
   }
}

void malloc_err(void)
{
   fprintf(stderr, "Error during memory allocation. Terminating...\n");
   exit(EXIT_FAILURE);
}

int compare_flows(const void *a, const void *b)
{
   if (((port_t *) a)->flows < ((port_t *) b)->flows) {
      return 1;
   } else if (((port_t *) a)->flows == ((port_t *) b)->flows) {
      return 0;
   } else {
      return -1;
   }
}

int compare_packets(const void *a, const void *b)
{
   if (((port_t *) a)->packets < ((port_t *) b)->packets) {
      return 1;
   } else if (((port_t *) a)->packets == ((port_t *) b)->packets) {
      return 0;
   } else {
      return -1;
   }
}

int compare_bytes(const void *a, const void *b)
{
   if (((port_t *) a)->bytes < ((port_t *) b)->bytes) {
      return 1;
   } else if (((port_t *) a)->bytes == ((port_t *) b)->bytes) {
      return 0;
   } else {
      return -1;
   }
}

int compare_flows_table(const void *a, const void *b)
{
   if (((ip_t *) a)->flows < ((ip_t *) b)->flows) {
      return 1;
   } else if (((ip_t *) a)->flows == ((ip_t *) b)->flows) {
      return 0;
   } else {
      return -1;
   }
}

int compare_packets_table(const void *a, const void *b)
{
   if (((ip_t *) a)->packets < ((ip_t *) b)->packets) {
      return 1;
   } else if (((ip_t *) a)->packets == ((ip_t *) b)->packets) {
      return 0;
   } else {
      return -1;
   }
}

int compare_bytes_table(const void *a, const void *b)
{
   if (((ip_t *) a)->bytes < ((ip_t *) b)->bytes) {
      return 1;
   } else if (((ip_t *) a)->bytes == ((ip_t *) b)->bytes) {
      return 0;
   } else {
      return -1;
   }
}
