/**
 * \file nfdump_reader.h
 * \brief Nfdump reader module reads a given nfdump file and outputs flow
 *  records in UniRec format.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>, Pavel Krobot <xkrobo01@cesnet.cz>
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
#define _BSD_SOURCE

/* Information if sigaction is available for nemea signal macro registration. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>

#include <unistd.h>
#include <sys/time.h> /* gettimeofday for real-time resending. */

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <libnf.h>
#include <nemea-common.h>

#include <real_time_sending.h>
#include "fields.h"

/* Defaults and parameters. */
#define DEFAULT_DIR_BIT_FIELD 0
#define DEFAULT_LINK_MASK "1"

#define MINIMAL_SENDING_RATE  100
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

/* Struct with information about module. */
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("nfdump_reader","This module reads a given nfdump file and outputs flow records in UniRec format. If more files are specified, all flows from the first file are read, then all flows from second file and so on.",0,1)

#define MODULE_PARAMS(PARAM) \
   PARAM('f', "filter", "A nfdump-like filter expression. Only records matching the filter will be sent to the output.", required_argument, "string") \
   PARAM('c', "first", "Read only the first N flow records.", required_argument, "uint64") \
   PARAM('n', "no_eof", "Don't send EOF message at the end.", no_argument, "none") \
   PARAM('T', "send_time", "Replace original timestamps by record actual sending time.", no_argument, "none") \
   PARAM('D', "DBF_record", "Fill DIR_BIT_FIELD according to record direction.", no_argument, "none") \
   PARAM('l', "link_mask", "Use link mask m for LINK_BIT_FIELD. m is 8-bit hexadecimal number e.g. m should be 1, c2, AB,...", required_argument, "string") \
   PARAM('p', "print", "Show progress - print a dot every N flows.", required_argument, "uint64") \
   PARAM('r', "rate", "Rate limiting. Limiting sending flow rate to N records/sec.", required_argument, "uint64") \
   PARAM('R', "resend", "Real time re-sending. Resending records from given files in real time, respecting original timestamps (seconds). Since this mode is timestamp order dependent, real time re-sending is done only at approximate time.", no_argument, "none") \
   PARAM('-', "", "Input files - one or more nfdump files to read.", required_argument, "string")


static int stop = 0;

/* Declares progress_printer variables. */
NMCM_PROGRESS_DECL

enum module_states{
   STATE_OK = 0,
   STATE_ERR = 3
};

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


void set_actual_timestamps(lnf_brec1_t *brec, void *out_rec, ur_template_t *tmplt){
   time_t act_time;
   uint64_t first;
   uint64_t last;

   time(&act_time);

   first = ur_time_from_sec_msec(act_time - (brec->last / 1000 - brec->first / 1000), brec->first % 1000);
   last = ur_time_from_sec_msec(act_time, brec->last % 1000);

   ur_set(tmplt, out_rec, F_TIME_FIRST, first);
   ur_set(tmplt, out_rec, F_TIME_LAST, last);
}

void delay_sending_rate(struct timeval *sr_start)
{
   struct timeval sr_end;

   gettimeofday(&sr_end, NULL);
   long sr_diff = ((sr_end.tv_sec * 1000000 + sr_end.tv_usec) - (sr_start->tv_sec * 1000000 + sr_start->tv_usec));
   if (sr_diff < 1000000) {
      usleep(1000000 - sr_diff);
   }
}

int main(int argc, char **argv)
{
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   /* General. */
   int module_state = STATE_OK;
   int ret;
   int verbose = 0;
   trap_ifc_spec_t ifc_spec;

   int send_eof = 1;
   unsigned long record_counter = 0;
   unsigned long max_records = 0;
   char *filter = NULL;
   uint8_t set_dir_bit_field = 0;
   char *link_mask = DEFAULT_LINK_MASK; /* 8 * sizeof(char) = 64 bits of uint64_t */
   ur_links_t *links;

   /* Declare progress struct, pointer to this struct, initialize progress limit. */
   NMCM_PROGRESS_DEF;
   /* Actual timestamps. */
   int actual_timestamps = 0;
   /* Rate limiting. */
   unsigned long sending_rate = 0;
   struct timeval sr_start;
   /* Real-time sendning. */
   uint8_t rt_sending = 0;
   rt_state_t rt_sending_state;
   /* libnf structures. */
   lnf_brec1_t brec;
   lnf_filter_t *filterp;

   /* Let TRAP library parse command-line arguments and extract its parameters. */
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { /* "-h" was found. */
         trap_print_help(module_info);
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 1;
   }

   verbose = (trap_get_verbose_level() >= 0);

   /* Parse remaining parameters. */
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'f':
            filter = optarg;
            break;
         case 'c':
            max_records = atoi(optarg);
            if (max_records == 0) {
               fprintf(stderr, "Invalid maximal number of records.\n");
               return 2;
            }
            break;
         case 'n':
            send_eof = 0;
            break;
         case 'D':
            set_dir_bit_field = 1;
            break;
         case 'l':
            link_mask = optarg;
            break;
         case 'p':
            NMCM_PROGRESS_INIT(atoi(optarg), return 2);
            break;
         case 'r':
            sending_rate = atoi(optarg);
            if (sending_rate < MINIMAL_SENDING_RATE) {
               fprintf(stderr, "Invalid sending rate (%i rec/s is minimum).\n", MINIMAL_SENDING_RATE);
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               return 2;
            }
            break;
         case 'R':
            rt_sending = 1;
            break;
         case 'T':
            actual_timestamps = 1;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            return 2;
      }
   }

   if (optind >= argc) {
      fprintf(stderr, "Wrong number of parameters.\nUsage: %s -i trap-ifc-specifier \
            [-f FILTER] [-n] [-c NUM] [-r NUM] [-R] [-T] [-l MASK] [-D] nfdump-file [nfdump-file...]\n", argv[0]);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 2;
   }

   links = ur_create_links(link_mask);
   if (links == NULL) {
      fprintf(stderr, "Invalid link mask.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 2;
   }

   if (sending_rate && rt_sending) {
      fprintf(stderr, "Wrong parameters, use only one of -r / -R.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 2;
   }

   /* Initialize TRAP library (create and init all interfaces). */
   if (verbose) {
      printf("Initializing TRAP library ...\n");
   }

   ret = trap_init(module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 4;
   }
   trap_free_ifc_spec(ifc_spec); /* We don't need ifc_spec anymore. */

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   /* Create UniRec template. */
   ur_template_t *tmplt = ur_create_output_template(0, BASIC_FLOW_TEMPLATE, NULL);
   if (tmplt == NULL) {
      trap_finalize();
      fprintf(stderr, "ERROR in allocation template\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 2;
   }
   /* Allocate memory for output UniRec record (0 bytes for dynamic fields). */
   void *rec_out = ur_create_record(tmplt, 0);

   if (rt_sending) {
      RT_INIT(rt_sending_state, 10, 1000, 100, 3.5, goto exit;);
   }

   if (verbose) {
      printf("Sending records ...\n");
   }

   lnf_rec_t *recp;
   lnf_file_t *filep;

   /* For all input files... */
   do {
      /* Open nfdump file. */
      if (verbose) {
         printf("Reading file %s\n", argv[optind]);
      }

      ret = lnf_open(&filep, argv[optind], LNF_READ, NULL);
      if (ret != LNF_OK) {
         fprintf(stderr, "Error when trying to open file \"%s\"\n", argv[optind]);
         module_state = STATE_ERR;
         goto exit;
      }

      if (sending_rate) {
         gettimeofday(&sr_start, NULL);
      }

      lnf_rec_init(&recp);

      if (filter != NULL && lnf_filter_init(&filterp, filter) != LNF_OK) {
         fprintf(stderr, "Can not init filter '%s'\n", filter);
         module_state = STATE_ERR;
         goto exit;
      }

       /* For all records in the file... */
      while (!stop && (max_records == 0 || record_counter < max_records)) {
         ret = lnf_read(filep, recp);
         if (filter != NULL && !lnf_filter_match(filterp, recp)) {
            continue;
         }

         /* Read a record from the file. */
         if (ret != LNF_OK) {
            if (ret == LNF_EOF) {
               break;
            }

            fprintf(stderr, "Error during reading file (%i).\n", ret);
            lnf_close(filep);
            module_state = STATE_ERR;
            goto exit;
         }

         lnf_rec_fget(recp, LNF_FLD_BREC1, &brec);
         /* Copy data from master_record_t to UniRec record. */
         if (!IN6_IS_ADDR_V4COMPAT(brec.srcaddr.data)) { /* IPv6 */
            ur_set(tmplt, rec_out, F_SRC_IP, ip_from_16_bytes_be((char *) &brec.srcaddr.data));
            ur_set(tmplt, rec_out, F_DST_IP, ip_from_16_bytes_be((char *) &brec.dstaddr.data));
         } else { /* IPv4 */
            ur_set(tmplt, rec_out, F_SRC_IP, ip_from_4_bytes_be((char *) &(brec.srcaddr.data[3])));
            ur_set(tmplt, rec_out, F_DST_IP, ip_from_4_bytes_be((char *) &(brec.dstaddr.data[3])));
         }

         ur_set(tmplt, rec_out, F_SRC_PORT, brec.srcport);
         ur_set(tmplt, rec_out, F_DST_PORT, brec.dstport);
         ur_set(tmplt, rec_out, F_PROTOCOL, brec.prot);
         ur_set(tmplt, rec_out, F_PACKETS, brec.pkts);
         ur_set(tmplt, rec_out, F_BYTES, brec.bytes);
         ur_set(tmplt, rec_out, F_LINK_BIT_FIELD, ur_get_link_mask(links));

         uint16_t flags;
         lnf_rec_fget(recp, LNF_FLD_TCP_FLAGS, &flags);
         ur_set(tmplt, rec_out, F_TCP_FLAGS, flags);

         uint32_t input;
         lnf_rec_fget(recp, LNF_FLD_INPUT, &input);
         if (set_dir_bit_field) {
            if (input > 0) {
               ur_set(tmplt, rec_out, F_DIR_BIT_FIELD, (1 << input));
            } else {
               ur_set(tmplt, rec_out, F_DIR_BIT_FIELD, DEFAULT_DIR_BIT_FIELD);
            }
         } else {
            ur_set(tmplt, rec_out, F_DIR_BIT_FIELD, DEFAULT_DIR_BIT_FIELD);
         }

         ur_set(tmplt, rec_out, F_TIME_FIRST, ur_time_from_sec_msec(brec.first / 1000, brec.first % 1000));
         ur_set(tmplt, rec_out, F_TIME_LAST, ur_time_from_sec_msec(brec.last / 1000, brec.last % 1000));

         if (rt_sending) {
            RT_CHECK_DELAY(record_counter, brec.last, rt_sending_state);
         }
         if (actual_timestamps) {
            set_actual_timestamps(&brec, rec_out, tmplt);
         }

         /* Send data to output interface. */
         trap_send(0, rec_out, ur_rec_fixlen_size(tmplt));
         record_counter++;

         if (sending_rate) {
            if ((record_counter % sending_rate) == 0) {
               delay_sending_rate(&sr_start);
               gettimeofday(&sr_start, NULL);
            }
         }

         /* Printing progress. */
         NMCM_PROGRESS_PRINT;

      } /* For all records in a file. */
      if (verbose) {
         printf("done.\n");
      }

      lnf_rec_free(recp);
      lnf_close(filep);
      if (filter != NULL) {
         lnf_filter_free(filterp);
      }
   } while (!stop && ++optind < argc); /* For all input files. */

   NMCM_PROGRESS_NEWLINE;
   printf("%lu flow records sent\n", record_counter);

   /* Send data with zero length to signalize end. */
   char dummy[1] = {0};
   if (!stop && send_eof) { /* If EOF enabled and program wasn't interrupted. */
      if (verbose) {
         printf("Sending EOF message (zero-length record)\n");
      }
      trap_send(0, dummy, 1); /* FIXME: zero-length messages doesn't work, send message of length 1 */
   }

exit:
   if (rt_sending) {
      RT_DESTROY(rt_sending_state);
   }
   trap_finalize();
   ur_free_record(rec_out);
   ur_free_template(tmplt);
   ur_free_links(links);
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   return module_state;
}
