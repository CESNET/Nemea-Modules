/**
 * \file traffic_merger_v2.c
 * \brief Merge traffic incoming on mutiple interfaces.
 * \author Pavel Krobot <xkrobo01@cesnet.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2013 CESNET
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
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <omp.h>

#define TS_LAST 	0
#define TS_FIRST	1
#define DEFAULT_TIMEOUT			10
#define DEFAULT_BUFFER_SIZE	20

#define INPUT_NOCHANGE 	0
#define INPUT_ADD			1
#define INPUT_REMOVE		-1
#define INPUT_INACTIVE	-2

#define MODE_TIME_IGNORE	0
#define MODE_TIME_AWARE		1

// Struct with information about module
trap_module_info_t module_info = {
   "Traffic Merger (2nd version)", // Module name
   // Module description
   "This module merges traffic from multiple input interfaces to one output\n"
   "interface. There are two supported versions:\n"
   "   - normal (default) - resending incoming data as they come.\n"
   "   - timestamp aware - incoming data are sended with respect to timestamp.\n"
   "     order.\n"
   "\n"
   "Interfaces:\n"
   "   Inputs: variable\n"
   "   Outputs: 1\n"
   "\n"
   "Usage:\n"
   "   ./merger -i IFC_SPEC -n CNT [-u IN_FMT] [-o OUT_FMT] [-T] [-F] [-s SIZE] [-t MS]\n"
   "\n"
   "Module specific parameters:\n"
   "   UNIREC_FMT   The i-th parameter of this type specifies format of UniRec\n"
   "                expected on the i-th input interface.\n"
   "   -F         (timestamp aware version) Sorts timestamps based on TIME_FIRST\n"
   "              field, instead of TIME_LAST (default).\n"
   "   -n CNT     Sets count of input links. Must correspond to parameter -i (trap).\n"
   "   -o OUT_FMT Set of fields included in the output (UniRec specifier).\n"
   "              (default <COLLECTOR_FLOW>).\n"
   "   -u IN_FMT  UniRec specifier of input data (same to all links).\n"
   "              (default <COLLECTOR_FLOW>).\n"
   "   -s SIZE    (timestamp aware version) Set size of buffer for incoming records.\n"
   "   -t MS      (timestamp aware version) Set initial timeout for incoming\n"
   "              interfaces (in miliseconds). Timeout is set to 0, if no data\n"
   "              received in initial timeout.\n"
   "   -T         Set mode to timestamp aware.\n",
   -1, // Number of input interfaces (-1 means variable)
   1, // Number of output interfaces
};

static int stop = 0;

int verbose;
static int n_inputs; // Number of input interfaces
static int active_inputs; // Number of active input interfaces
static int initial_timeout = DEFAULT_TIMEOUT; // Initial timeout for incoming interfaces (in miliseconds)
static int timestamp_selector = TS_LAST; // Tells to sort timestamps based on TIME_FIRST or TIME_LAST field
static int *rcv_flag_field; // Flag field for input interfaces
static int rcv_read_flag = 0; // Receive counter for active input interfaces
static int send_index = -1; // Index of interface with privilege to send
static ur_time_t actual_timestamp = 0; // Actual minimal timestamp
static int ready_to_send = 0;
static ur_template_t *in_template; // UniRec template of input interface(s)
static ur_template_t *out_template; // UniRec template of output interface
static int buffer_size = DEFAULT_BUFFER_SIZE; // Size of buffer for input records
static void **rec_buffs; // Buffer for input records

unsigned int num_records = 0; // Number of records received (total of all inputs)

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

void ta_capture_thread(int index)
{
   int ret;
   int read_next = 1;
   int input_state = INPUT_NOCHANGE;
   int timeout = initial_timeout;

	ur_time_t rec_time;

   if (verbose >= 1) {
      printf("Thread %i started.\n", index);
   }

//   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, timeout);
   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_WAIT);

   // Read data from input and log them to a file
   while (!stop) {
		const void *rec;
		uint16_t rec_size;

		if (read_next){
			if (verbose >= 2) {
				printf("Thread %i: calling trap_recv()\n", index);
			}
			// Receive data from index-th input interface, wait until data are available
//			ret = trap_get_data(ifc_mask, &rec, &rec_size, TRAP_WAIT);
			ret = trap_recv(index, &rec, &rec_size);
//			printf("Rec...\n");
			if (ret != TRAP_E_OK) {
				if (ret == TRAP_E_TIMEOUT) {//input probably (temporary) offline
					printf("Thread %i: no data received (timeout %u).\n", index, timeout);
					timeout = 0;
					trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
					input_state = INPUT_REMOVE;
				} else if (ret == TRAP_E_TERMINATED) {
					break; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
				} else {
					// Some error has occured
					fprintf(stderr, "Error: trap_get_data() returned %i (%s)\n", ret, trap_last_error_msg);
					break;
				}
			} else {
				if (input_state == INPUT_REMOVE){//input is online again
					timeout = initial_timeout;
//					trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, timeout);
					trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_WAIT);
					input_state = INPUT_ADD;
				}

				if (verbose >= 2) {
					printf("Thread %i: received %hu bytes of data\n", index, rec_size);
				}

				// Check size of received data
				if (rec_size < ur_rec_static_size(in_template)) {
					if (rec_size <= 1) {
						if (verbose >= 0) {
							printf("Interface %i received ending record, the interface will be closed.\n", index, rec_size);
							input_state = INPUT_REMOVE;
						}
						stop = 1;
					} else {
						fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
								  ur_rec_static_size(in_template), rec_size);
						break;
					}
				}

				if (timestamp_selector == TS_FIRST){
					rec_time = ur_get(in_template, rec, UR_TIME_FIRST);
				} else {
					rec_time = ur_get(in_template, rec, UR_TIME_LAST);
				}
//				printf("%lu\n", rec_time);
				read_next = 0;
			}
		}

      #pragma omp critical
      {
      	if (input_state == INPUT_ADD){
				++n_inputs;
				printf("adding input: %i\n", n_inputs);
				input_state = INPUT_NOCHANGE;
      	} else if (input_state == INPUT_REMOVE){
				--n_inputs;
				printf("removing input: %i\n", n_inputs);
				input_state = INPUT_INACTIVE;
      	}
      	if (input_state == INPUT_NOCHANGE){
				if (!rcv_flag_field[index]){
					if (actual_timestamp == 0 || actual_timestamp > rec_time){
						actual_timestamp = rec_time;
						send_index = index;
					}
					++rcv_read_flag;
					rcv_flag_field[index] = 1;
				}

				if (rcv_read_flag >= n_inputs){
					if (send_index == index){
						ret = trap_send_data(0, rec, rec_size, TRAP_WAIT);
						if (ret != TRAP_E_OK) {
							if (ret == TRAP_E_TERMINATED) {
								stop = 1; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
							} else {
								// Some error has occured
								fprintf(stderr, "Error: trap_send_data() returned %i (%s)\n", ret, trap_last_error_msg);
								stop = 1;
							}
	//						TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0; continue, break);
						}
						rcv_read_flag = 0;
						memset(rcv_flag_field, 0, n_inputs * sizeof(int));
						actual_timestamp = 0;
						send_index = -1;
						read_next = 1;
					}
				}
			}
		} // end critical section
   } // end while(!stop)

   if (verbose >= 1) {
      printf("Thread %i exitting.\n", index);
   }
}

void capture_thread(int index)
{
	int private_stop = 0;
   int ret;
   int timeout = initial_timeout;

   if (verbose >= 1) {
      printf("Thread %i started.\n", index);
   }

//   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, timeout);
   trap_ifcctl(TRAPIFC_INPUT, index, TRAPCTL_SETTIMEOUT, TRAP_WAIT);

   // Read data from input and log them to a file
   while (!stop && !private_stop) {
		const void *rec;
		uint16_t rec_size;

		if (verbose >= 2) {
			printf("Thread %i: calling trap_recv()\n", index);
		}
		// Receive data from index-th input interface, wait until data are available
		ret = trap_recv(index, &rec, &rec_size);
		TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

		if (verbose >= 2) {
			printf("Thread %i: received %hu bytes of data\n", index, rec_size);
		}

		// Check size of received data
		if (rec_size < ur_rec_static_size(in_template)) {
			if (rec_size <= 1) {
				if (verbose >= 0) {
					printf("Interface %i received ending record, the interface will be closed.\n", index, rec_size);
				}
				private_stop = 1;
				if (--active_inputs > 0){// Only last thread send terminating message.
					break;
				}
			} else {
				fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
						  ur_rec_static_size(in_template), rec_size);
				break;
			}
		}

      #pragma omp critical
      {
			ret = trap_send_data(0, rec, rec_size, TRAP_WAIT);
//			TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
			if (ret != TRAP_E_OK) {
				if (ret == TRAP_E_TERMINATED) {
					private_stop = 1; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
				} else {
					// Some error has occured
					fprintf(stderr, "Error: trap_send_data() returned %i (%s)\n", ret, trap_last_error_msg);
					private_stop = 1;
				}
			}
		} // end critical section
   } // end while(!stop && !private_stop)

   if (verbose >= 1) {
      printf("Thread %i exitting.\n", index);
   }
}


int main(int argc, char **argv)
{
   int ret;
   int mode=MODE_TIME_IGNORE;
   char *in_template_str = "<COLLECTOR_FLOW>";
   char *out_template_str = "<COLLECTOR_FLOW>";

   // ***** Process parameters *****

   // Let TRAP library parse command-line arguments and extract its parameters
   trap_ifc_spec_t ifc_spec;
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }

   verbose = trap_get_verbose_level();

   if (verbose >= 0){
      printf("Verbosity level: %i\n", trap_get_verbose_level());
   }

   // Parse remaining parameters and get configuration
   char opt;
   while ((opt = getopt(argc, argv, "Fn:o:u:s:t:T")) != -1) {
      switch (opt) {
         case 'F':
            timestamp_selector = TS_FIRST;
            break;
			case 'n':
            n_inputs = atoi(optarg);
            break;
         case 'o':
            out_template_str = optarg;
            break;
			case 'u':
            in_template_str = optarg;
            break;
			case 's':
				buffer_size = atoi(optarg);
				break;
			case 't':
            initial_timeout = atoi(optarg);
            break;
			case 'T':
				mode=MODE_TIME_AWARE;
				break;
         default:
            fprintf(stderr, "Error: Invalid arguments.\n");
            return 1;
      }
   }

   if (verbose >= 0) {
      printf("Number of inputs: %i\n", n_inputs);
   }
   if (n_inputs > 32) {
      fprintf(stderr, "Error: More than 32 interfaces is not allowed by TRAP library.\n");
      return 4;
   }

	active_inputs = n_inputs;

   if (verbose >= 0) {
      printf("Creating UniRec templates ...\n");
   }

   // Create input UniRec template
	in_template = ur_create_template(in_template_str);
	if (in_template == NULL) {
		fprintf(stderr, "Error: Invalid template: %s\n", in_template_str);
		ret = -1;
		goto exit;
	}
   // Create output UniRec template
	out_template = ur_create_template(out_template_str);
	if (out_template == NULL) {
		fprintf(stderr, "Error: Invalid template: %s\n", out_template_str);
		ret = -1;
		goto exit;
	}

   // ***** TRAP initialization *****

   // Set number of input interfaces
   module_info.num_ifc_in = n_inputs;

   if (verbose >= 0) {
      printf("Initializing TRAP library ...\n");
   }

   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      trap_free_ifc_spec(ifc_spec);
      ret = 2;
      goto exit;
   }

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

	if (mode == MODE_TIME_AWARE){
		rcv_flag_field = (int *) malloc(n_inputs * sizeof(int));
		memset(rcv_flag_field, 0, n_inputs * sizeof(int));
	}

   if (verbose >= 0) {
      printf("Initialization done.\n");
   }

	if (mode == MODE_TIME_AWARE){ ///** TMP - TODO
		printf("Mode not implemented yet.\n");
		goto exit;
	}

   // ***** Start a thread for each interface *****
   #pragma omp parallel num_threads(n_inputs)
   {
//   	if (mode == MODE_TIME_AWARE)
//			ta_capture_thread(omp_get_thread_num());
//		else
			capture_thread(omp_get_thread_num());
   }

   ret = 0;

   // ***** Cleanup *****

exit:
   if (verbose >= 0) {
      printf("Exitting ...\n");
   }

   trap_terminate(); // This have to be called before trap_finalize(), otherwise it may crash (don't know if feature or bug in TRAP)

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(in_template);
   ur_free_template(out_template);

	if (mode == MODE_TIME_AWARE){
		free(rcv_flag_field);
	}

   return ret;
}

