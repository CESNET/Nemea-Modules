/**
 * \file nfd_test_receiver.c
 * \brief Test receiver for nfdump reader.
 * \author Pavel Krobot <Pavel.Krobot@cesnet.cz>
 * \date 2013
 * \date 2014
 */
/*
 * Copyright (C) 2013,2014 CESNET
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <getopt.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.c"

/* Struct with information about module. */
trap_module_info_t *module_info = NULL;

#define BASIC_FLOW_TEMPLATE "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL"

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint8 TOS,
   uint8 TTL
)

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("Test receiver module for nfdump reader.", \
   "This module reveiving UniRec messages from nfdump reader and print received\n" \
   "messages (counts) to stdout. In default, it prints received messages in format\n" \
    " <CNT>. <TIME_FIRST> | <TIME_LAST>. If parameter -t N is set, output will be\n" \
    "switched to \"counter\" mode and it outputs counts of received messages every\n" \
    "N seconds." \
    "Interfaces:\n" \
   , 1, 0)

#define MODULE_PARAMS(PARAM) \
  PARAM('D', "difference", "Set differences.", no_argument, "none") \
  PARAM('t', "counter", "Switch output to 'counter' mode, outputing counts of received messages every N seconds.", required_argument, "int32") \
  PARAM('F', "field", "Set fields.", no_argument, "none")

static int stop = 0;

/* Function to handle SIGTERM and SIGINT signals (used to stop the module). */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

int main(int argc, char **argv)
{
   int ret;
   trap_ifc_spec_t ifc_spec;
   int time_interval = 0;
   int init_flag = 1;
   uint32_t fields = 0;
   uint32_t differences = 0;
   uint32_t act_time;
   uint32_t next_time;
   uint32_t first;
   uint32_t last;
   uint64_t msg_counter = 0;
   uint64_t act_msg_counter = 0;

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   /* Let TRAP library parse command-line arguments and extract its parameters. */
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { /* "-h" was found. */
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }

   /* Parse remaining parameters. */
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'D':
            differences = 1;
            break;
         case 't':
            time_interval = atoi(optarg);
            if (time_interval == 0) {
               fprintf(stderr, "Invalid time interval (-t).\n");
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               return 2;
            }
         case 'F':
            fields = 1;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            return 2;
      }
   }

   if (optind > argc) {
      fprintf(stderr, "Wrong number of parameters.\nUsage: %s -i trap-ifc-specifier [-t N]\n", argv[0]);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 2;
   }

   if (differences && fields) {
      fprintf(stderr, "Wrong parameters, use only one of \"-F\" or \"-D\"\n.");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 2;
   }

   /* Initialize TRAP library (create and init all interfaces). */
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 4;
   }

   trap_free_ifc_spec(ifc_spec); /* We don't need ifc_spec anymore. */



   /* Create UniRec templates. */
   ur_template_t *in_tmplt = ur_create_input_template(0, BASIC_FLOW_TEMPLATE, NULL);

   /* Main processing loop. */

   /* Read data from input, process them and write to output. */
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      /* Receive data from any input interface, wait until data are available. */
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      /* Handle possible errors. */
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      /* Check size of received data. */
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; /* End of data (used for testing purposes). */
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      /* Process the data. */
      ++msg_counter;
      first = ur_time_get_sec(ur_get(in_tmplt, in_rec, F_TIME_FIRST));
      last = ur_time_get_sec(ur_get(in_tmplt, in_rec, F_TIME_LAST));

      if (time_interval) {
         if (init_flag) {
            init_flag = 0;
            act_time = first;
            next_time = act_time + time_interval;
         }
         if (first >= next_time) {
            printf("Time interval %lu - %lu: %llu messages.\n", act_time, next_time, msg_counter - act_msg_counter);
            act_time = first;
            next_time = act_time + time_interval;
            act_msg_counter = msg_counter;
         }
      } else if (differences) {
         printf("%llu. %lu\n", msg_counter, last - first);
      } else if (fields) {
         printf("%llu. L:%lu D:%i\n", msg_counter, ur_get(in_tmplt, in_rec, F_LINK_BIT_FIELD), ur_get(in_tmplt, in_rec, F_DIR_BIT_FIELD));
      } else {
         printf("%llu. %lu | %lu\n", msg_counter, first, last);
      }

   }

   /* Cleanup. */
   if (time_interval) {
      printf("Time interval %lu - %lu: %llu messages.\n", act_time, next_time, msg_counter - act_msg_counter);
   }
   fprintf(stderr, "TOTAL RECEIVED MESSAGES: %llu\n", msg_counter);

   /* Do all necessary cleanup before exiting. */
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(in_tmplt);
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   return 0;
}

