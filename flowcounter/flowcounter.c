/**
 * \file flow_counter.h
 * \brief Example module for counting number of incoming flow records.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
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

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <nemea-common.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

#define INTERVAL_LIMIT 1000   /* send interval limit */

/* error handling macros */
#define HANDLE_PERROR(msg) \
   do { perror(msg); exit(EXIT_FAILURE); } while(0)
#define HANDLE_ERROR(msg) \
   do { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); } while (0)

UR_FIELDS(
   uint32 PACKETS,     //Number of packets in a flow or in an interval
   uint64 BYTES,       //Number of bytes in a flow or in an interval
   uint64 FLOWS,       //Number of flows
)

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("flowcounter","Example module for counting number of incoming flow records.",1,0)

#define MODULE_PARAMS(PARAM) \
   PARAM('p', "print", "Show progress - print a dot every N flows.", required_argument, "int32") \
   PARAM('P', "print_c", "When showing progress, print CHAR instead of dot.", required_argument, "string") \
   PARAM('o', "send_time", "Send @VOLUME record filled with current counters every SEC second(s).", required_argument, "int32")




/* ************************************************************************* */

static int stop = 0;
static int stats = 0;
static unsigned long cnt_flows = 0, cnt_packets = 0, cnt_bytes = 0;

static unsigned long send_interval; /* data sending interval */
ur_template_t *out_tmplt;           /* output template */
void *out_rec;                      /* output record */


// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

// Declares progress structure prototype
NMCM_PROGRESS_DECL

void signal_handler(int signal)
{
   if (signal == SIGUSR1) {
      stats = 1;
   }
}

void send_handler(int signal)
{
   int ret;

   if (signal != SIGALRM) {
      return;
   }

   ur_set(out_tmplt, out_rec, F_FLOWS, cnt_flows);
   ur_set(out_tmplt, out_rec, F_PACKETS, cnt_packets);
   ur_set(out_tmplt, out_rec, F_BYTES, cnt_bytes);
   ret = trap_send(0, out_rec, ur_rec_fixlen_size(out_tmplt));
   TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, goto set_alarm, exit(EXIT_FAILURE));
set_alarm:
   alarm(send_interval);
}

void get_o_param(int argc, char **argv, const char *module_getopt_string, const struct option *long_options)
{
   /* backup global variables */
   int bck_optind = optind, bck_optopt = optopt, bck_opterr = opterr;
   char *bck_optarg = optarg;
   signed char opt;

   // Add "i:" to getopt_string
   /* This is necessary because getopt rearragnes arguments in such a way that
      all positional agruments (i.e. not options) are put at the end of argv.
      If it wouldn't know about "-i" and that it requires argument, it would
      move the argument (ifc specifier) to the end of argv (but doesn't move 
      the "-i").
      trap_parse_params (within TRAP_DEFAULT_INITIALIZATION) would than fail.
   */
   char *getopt_string_with_i = malloc(strlen(module_getopt_string) + 3);
   sprintf(getopt_string_with_i, "%s%s", module_getopt_string, "i:");

   opterr = 0;                  /* disable getopt error output */
   while ((opt = TRAP_GETOPT(argc, argv, getopt_string_with_i, long_options)) != -1) {
      switch (opt) {
      case 'o':
         {
            char *endptr;
            long int tmp_interval;

            errno = 0;
            tmp_interval = strtol(optarg, &endptr, 0);
            if (errno) {
               HANDLE_PERROR("-o");
            } else if (*optarg == '\0') {
               HANDLE_ERROR("-o: missing argument");
            } else if (*endptr != '\0') {
               HANDLE_ERROR("-o: bad argument");
            } else if (tmp_interval <= 0 || tmp_interval >= INTERVAL_LIMIT) {
               HANDLE_ERROR("-o: bad interval range");
            }
            send_interval = tmp_interval;
            break;
         }
      default:
         if (optopt == 'o') {
            HANDLE_ERROR("-o: missing argument");
         }
         break;
      }
   }

   free(getopt_string_with_i);

   /* restore global variables */
   optind = bck_optind;
   optopt = bck_optopt;
   opterr = bck_opterr;
   optarg = bck_optarg;
}

int main(int argc, char **argv)
{
	int ret;
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // Declare progress structure, pointer to this struct, initialize progress limit
   NMCM_PROGRESS_DEF;

   get_o_param(argc, argv, module_getopt_string, long_options);     /* output have to be known before TRAP init */

   // ***** TRAP initialization *****
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER(); // Handles SIGTERM and SIGINT
   signal(SIGUSR1, signal_handler);
   signal(SIGALRM, send_handler);

   // ***** Create UniRec template *****
   char *unirec_specifier = "PACKETS,BYTES";
   signed char opt;

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'p':
         NMCM_PROGRESS_INIT(atoi(optarg), return 1);
         break;
      case 'P':
         nmcm_progress_ptr->print_char = optarg[0];
         break;
      case 'o':
         /* proccessed earlier */
         break;
      default:
         fprintf(stderr, "Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return 3;
      }
   }

   ur_template_t *tmplt = ur_create_input_template(0, unirec_specifier, NULL);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 4;
   }

   if (send_interval) {           /* in case of -o option */
      /* create new output tempate */
      out_tmplt = ur_create_output_template(0,"FLOWS,PACKETS,BYTES", NULL);
      if (!out_tmplt) {
         fprintf(stderr, "Error: Invalid UniRec specifier (this is implementation error, contact author of the module).\n");
         trap_finalize();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         ur_free_template(tmplt);
         return 4;
      }
      /* allocate space for output record with no dynamic part */
      out_rec = ur_create_record(out_tmplt, 0);
      if (!out_rec) {
         ur_free_template(out_tmplt);
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         ur_free_template(tmplt);
         ur_free_template(out_tmplt);
         return 4;
      }
      /* Set NO_WAIT to output interface */
      ret = trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
      if (ret != TRAP_E_OK) {
         ur_free_template(tmplt);
         ur_free_template(out_tmplt);
         ur_free_record(out_rec);
         fprintf(stderr, "Error: trap_ifcctl.\n");
         trap_finalize();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 4;
      }
      alarm(send_interval);     /* arrange SIGARLM in send_interval seconds */
   }

   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from input interface (block until data are available)
      const void *data;
      uint16_t data_size;
      ret = TRAP_RECEIVE(0, data, data_size, tmplt);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      // Check for end-of-stream message
      if (data_size <= 1) {
         break;
      }

      // Printing progress
      NMCM_PROGRESS_PRINT;

      // Update counters
      cnt_flows += 1;
      cnt_packets += ur_get(tmplt, data, F_PACKETS);
      cnt_bytes += ur_get(tmplt, data, F_BYTES);
      if (stats == 1) {
         printf("Time: %lu\n", (long unsigned int)time(NULL));
         printf("Flows:   %20lu\n", cnt_flows);
         printf("Packets: %20lu\n", cnt_packets);
         printf("Bytes:   %20lu\n", cnt_bytes);
         signal(SIGUSR1, signal_handler);
         stats = 0;
      }
   }

   // ***** Print results *****

   NMCM_PROGRESS_NEWLINE;
   printf("Flows:   %20lu\n", cnt_flows);
   printf("Packets: %20lu\n", cnt_packets);
   printf("Bytes:   %20lu\n", cnt_bytes);

   // ***** Cleanup *****

   alarm(0); // Potential pending alarm have to be cancelled before cleanup

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   if (send_interval) {         /* in case of -o option */
      ur_free_template(out_tmplt);
      ur_free_record(out_rec);
   }

   ur_finalize();
   ur_free_template(tmplt);
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return EXIT_SUCCESS;
}
