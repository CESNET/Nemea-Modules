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

#define INTERVAL_LIMIT 1000	  /* send interval limit */

/* error handling macros */
#define HANDLE_PERROR(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while(0)
#define HANDLE_ERROR(msg) \
	do { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); } while(0)

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
	"Flow-counter module",		  // Module name
	// Module description
	"Example module for counting number of incoming flow records.\n"
		 "Parameters:\n"
		 "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
		 "   -p N        Show progress - print a dot every N flows.\n"
		 "   -P CHAR     When showing progress, print CHAR instead of dot.\n"
		 "   -o SEC      Send @VOLUME record filled with current counters every SEC second(s).\n"
		 "Interfaces:\n"
		 "   Inputs: 1 (flow records)\n" "   Outputs: 0/1 (affected by -o parameter)\n",
	1,									  // Number of input interfaces
	0,									  // Number of output interfaces
	2,
	"-h", "--help", "prints help", 0, NULL,
	"-c", "--cell", "cell test", 0, NULL
};

/* ************************************************************************* */

static int stop = 0;
static int stats = 0;
static unsigned long cnt_flows = 0, cnt_packets = 0, cnt_bytes = 0;

static unsigned long send_interval;	/* data sending interval */
ur_template_t *out_tmplt;		  /* output template */
void *out_rec;						  /* output record */


// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

// Declares progress structure prototype
NMCM_PROGRESS_DECL

void signal_handler(int signal)
{
	/*if (signal == SIGTERM || signal == SIGINT) {
		stop = 1;
		trap_terminate();
	} else*/ if (signal == SIGUSR1) {
		stats = 1;
	}
}

void send_handler(int signal)
{
	int ret;

	if (signal != SIGALRM) {
		return;
	}

	ur_set(out_tmplt, out_rec, UR_FLOWS, cnt_flows);
	ur_set(out_tmplt, out_rec, UR_PACKETS, cnt_packets);
	ur_set(out_tmplt, out_rec, UR_BYTES, cnt_bytes);
	ret = trap_send(0, out_rec, ur_rec_static_size(out_tmplt));
	TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, exit(EXIT_FAILURE), exit(EXIT_FAILURE));
	alarm(send_interval);
}

void get_o_param(int argc, char **argv)
{
	/* backup global variables */
	int bck_optind = optind, bck_optopt = optopt, bck_opterr = opterr;
	char *bck_optarg = optarg, opt;

	opterr = 0;						  /* disable getopt error output */
	while ((opt = getopt(argc, argv, "-o:")) != -1) {
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
				module_info.num_ifc_out = 1;
				break;
			}
		default:
			if (optopt == 'o') {
				HANDLE_ERROR("-o: missing argument");
			}
			break;
		}
	}

	/* restore global variables */
	optind = bck_optind;
	optopt = bck_optopt;
	opterr = bck_opterr;
	optarg = bck_optarg;
}

int main(int argc, char **argv)
{
	int ret;

	// Declare progress structure, pointer to this struct, initialize progress limit
	NMCM_PROGRESS_DEF;

	get_o_param(argc, argv);	  /* output have to be known before TRAP init */

	// ***** TRAP initialization *****
	TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

	// Register signal handler.
	TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
	//signal(SIGTERM, signal_handler);
	//signal(SIGINT, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGALRM, send_handler);

	// ***** Create UniRec template *****
	char *unirec_specifier = "<COLLECTOR_FLOW>", opt;

	while ((opt = getopt(argc, argv, "u:p:P:o:")) != -1) {
		switch (opt) {
		case 'u':
			unirec_specifier = optarg;
			break;
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
			return 3;
		}
	}

	ur_template_t *tmplt = ur_create_template(unirec_specifier);
	if (tmplt == NULL) {
		fprintf(stderr, "Error: Invalid UniRec specifier.\n");
		trap_finalize();
		return 4;
	}

	if (send_interval) {			  /* in case of -o option */
		/* create new output tempate */
		out_tmplt = ur_create_template("<VOLUME>");
		if (!out_tmplt) {
			fprintf(stderr, "Error: Invalid UniRec specifier.\n");
			trap_finalize();
			return 4;
		}
		/* allocate space for output record with no dynamic part */
		out_rec = ur_create(out_tmplt, 0);
		if (!out_rec) {
			ur_free_template(out_tmplt);
			TRAP_DEFAULT_FINALIZATION();
			return 4;
		}
		ret = trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
		if (ret != TRAP_E_OK) {
			ur_free_template(out_tmplt);
			ur_free(out_rec);
			fprintf(stderr, "Error: trap_ifcctl.\n");
			trap_finalize();
			return 4;
		}
		alarm(send_interval);	  /* arrange SIGARLM in send_interval seconds */
	}

	// ***** Main processing loop *****
	while (!stop) {
		// Receive data from input interface (block until data are available)
		const void *data;
		uint16_t data_size;
		ret = trap_recv(0, &data, &data_size);
		TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

		// Check size of received data
		if (data_size < ur_rec_static_size(tmplt)) {
			if (data_size <= 1) {
				break;				  // End of data (used for testing purposes)
			} else {
				fprintf(stderr,
						  "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
						  ur_rec_static_size(tmplt), data_size);
				break;
			}
		}

      // Printing progress
      NMCM_PROGRESS_PRINT;

		// Update counters
		cnt_flows += 1;
		cnt_packets += ur_get(tmplt, data, UR_PACKETS);
		cnt_bytes += ur_get(tmplt, data, UR_BYTES);
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

	// Do all necessary cleanup before exiting
	TRAP_DEFAULT_FINALIZATION();

	if (send_interval) {			  /* in case of -o option */
		ur_free_template(out_tmplt);
		ur_free(out_rec);
		alarm(0);
	}

	ur_free_template(tmplt);

	return EXIT_SUCCESS;
}
