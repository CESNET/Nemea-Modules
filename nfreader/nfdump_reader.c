/**
 * \file nfdump_reader.h
 * \brief Nfdump reader module reads a given nfdump file and outputs flow
 *  records in UniRec format.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 */
#define _BSD_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>

#include <unistd.h>

#include <libtrap/trap.h>
#include "nfreader.h"
#include "../../unirec/unirec.h"


// Struct with information about module
trap_module_info_t module_info = {
   (char *) "Nfdump-reader module", // Module name
   // Module description
   (char *) "This module reads a given nfdump file and outputs flow records in \n"
   "UniRec format. If more files are specified, all flows from the first file\n"
   "are read, then all flows from second file and so on.\n"
   "\n"
   "Interfaces:\n"
   "   Inputs: 0\n"
   "   Outputs: 1 (<COLLECTOR_FLOW>) [FIXME: Not all fields are filled]\n"
   "\n"
   "Usage:\n"
   "   ./nfdump_reader -i IFC_SPEC [-c N] [-n] FILE [FILE...]"
   "\n"
   "   FILE   A file in nfdump format.\n"
   "   -c N   Read only the first N flow records.\n"
   "   -r N   Rate limiting. Limiting sending flow rate to N records/sec.\n"
   "   -R     Real time re-sending. Resending records from given files in real\n"
   "          time, respecting original timestamps (seconds).\n"
   "   -n     Don't send \"EOF message\" at the end.\n"
   "   -T     Sent data from files with timestamps based on actual time.\n"
   "",
   0, // Number of input interfaces
   1, // Number of output interfaces
};

#define COMMONTIMEOUT TRAP_WAIT
//#define COMMONTIMEOUT TRAP_HALFWAIT

static int stop = 0;

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   }
}

int main(int argc, char **argv)
{
   int ret;
   nf_file_t file;
   trap_ifc_spec_t ifc_spec;
   unsigned long counter = 0;
   unsigned long max_records = 0;
   int send_eof = 1;
   int verbose = 0;
   //------------ Actual timestamps --------------------------------------------
	int actual_timestamps = 0;
   time_t act_time;
   uint64_t first;
	uint64_t last;
	//------------ Rate limiting & Real time re-sending -------------------------
	long rec_to_send;
	unsigned long sending_rate = 0;
	unsigned long rt_resending = 0;
	unsigned long burst_size;
	unsigned long minimal_burst;
	unsigned long burst_counter;
	unsigned int sleeper;
	unsigned int init_flag;
	uint64_t load_index;
	uint64_t cmp_index;
	time_t sec;
	time_t next_sec;
	int time_diff_flag;
	int sleep_available;
	uint32_t timestamp_diff;
	uint32_t act_timestamp;

   // Create UniRec template
   //ur_template_t *tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS");
   ur_template_t *tmplt = ur_create_template("<COLLECTOR_FLOW>");
   //ur_template_t *tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD");

   // Let TRAP library parse command-line arguments and extract its parameters
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }

   verbose = (trap_get_verbose_level() >= 0);

   // Parse remaining parameters
   char opt;
   while ((opt = getopt(argc, argv, "c:nr:RT")) != -1) {
      switch (opt) {
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
			case 'r':
            sending_rate = atoi(optarg);
            if (sending_rate < MINIMAL_SENDING_RATE) {
               fprintf(stderr, "Invalid sending rate (%i rec/s is minimum).\n", MINIMAL_SENDING_RATE);
               return 2;
            }
            minimal_burst = sending_rate / MINIMAL_BURST_RATE;
            break;
			case 'R':
            rt_resending = 1;
            break;
			case 'T':
            actual_timestamps = 1;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 2;
      }
   }

   if (optind >= argc) {
      fprintf(stderr, "Wrong number of parameters.\nUsage: %s -i trap-ifc-specifier \
				[-n] [-c NUM] [-r NUM] nfdump-file [nfdump-file...]\n", argv[0]);
      return 2;
   }

	if (sending_rate && rt_resending){
		fprintf(stderr, "Wrong parameters, use only one of -r / -R.\n");
	}

   // Initialize TRAP library (create and init all interfaces)
   if (verbose) {
      printf("Initializing TRAP library ...\n");
   }
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      return 4;
   }
   trap_free_ifc_spec(ifc_spec); // We don't need ifc_spec anymore

   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);

	if (trap_ifcctl(TRAPIFC_OUTPUT, 0,TRAPCTL_BUFFERSWITCH, "0") != TRAP_E_OK){
		fprintf(stderr, "Error while turning off buffering.\n");
	}

   if (verbose) {
      printf("Sending records ...\n");
   }

   // Allocate memory for output UniRec record (0 bytes for dynamic fields)
   void *rec2 = ur_create(tmplt, 0);

   srand(time(NULL));

	if (sending_rate){
		burst_size = sending_rate;
		sleeper = 0;
	}else if (rt_resending){
		sleep_available = 1;
	}

   // For all input files...
   do {
      // Open nfdump file
      if (verbose) {
         printf("Reading file %s\n", argv[optind]);
      }
      ret = nf_open(&file, argv[optind]);
      if (ret != 0) {
         fprintf(stderr, "Error when trying to open file \"%s\"\n", argv[optind]);
         trap_finalize();
         ur_free(rec2);
         return 3;
      }
      if(sending_rate){
			time(&sec);
			time(&next_sec);
			rec_to_send = 0;
      }else if (rt_resending){
			init_flag = 1;
      }

      // For all records in the file
      while (!stop && (max_records == 0 || counter < max_records) && !ret) {
			master_record_t rec;

			time_diff_flag = 1;

			if (sending_rate) {
				load_index = 0;
				time(&next_sec);
				++next_sec;
				rec_to_send += sending_rate;
			}else{
				rec_to_send = 1;
				burst_size = 1;
			}

			while (!stop && (max_records == 0 || counter < max_records) && time_diff_flag && !ret) {
				if (rec_to_send > 0) {
					burst_counter = 0;
					while (!stop && (burst_counter < burst_size)) {
						// Read a record from the file
						ret = nf_next_record(&file, &rec);
						if (ret != 0) {
							if (ret == 1) { // no more records
								break;
							}
							fprintf(stderr, "Error during reading file.\n");
							nf_close(&file);
							trap_finalize();
							ur_free(rec2);
							return 3;
						}

						// Copy data from master_record_t to UniRec record
						if (rec.flags & 0x01) { // IPv6
							uint64_t tmp_ip_v6_addr;
							// Swap IPv6 halves
							tmp_ip_v6_addr = rec.ip_union._v6.srcaddr[0];
							rec.ip_union._v6.srcaddr[0] = rec.ip_union._v6.srcaddr[1];
							rec.ip_union._v6.srcaddr[1] = tmp_ip_v6_addr;
							tmp_ip_v6_addr = rec.ip_union._v6.dstaddr[0];
							rec.ip_union._v6.dstaddr[0] = rec.ip_union._v6.dstaddr[1];
							rec.ip_union._v6.dstaddr[1] = tmp_ip_v6_addr;

							ur_set(tmplt, rec2, UR_SRC_IP, ip_from_16_bytes_le((char *)rec.ip_union._v6.srcaddr));
							ur_set(tmplt, rec2, UR_DST_IP, ip_from_16_bytes_le((char *)rec.ip_union._v6.dstaddr));
						}
						else { // IPv4
							ur_set(tmplt, rec2, UR_SRC_IP, ip_from_4_bytes_le((char *)&rec.ip_union._v4.srcaddr));
							ur_set(tmplt, rec2, UR_DST_IP, ip_from_4_bytes_le((char *)&rec.ip_union._v4.dstaddr));

						}
						ur_set(tmplt, rec2, UR_SRC_PORT, rec.srcport);
						ur_set(tmplt, rec2, UR_DST_PORT, rec.dstport);
						ur_set(tmplt, rec2, UR_PROTOCOL, rec.prot);
						ur_set(tmplt, rec2, UR_TCP_FLAGS, rec.tcp_flags);
						ur_set(tmplt, rec2, UR_PACKETS, rec.dPkts);
						ur_set(tmplt, rec2, UR_BYTES, rec.dOctets);

						if (rt_resending){
							if (init_flag){
								init_flag = 0;
								act_timestamp = rec.last;
								time(&next_sec);
							}

							if (rec.last > act_timestamp){
								timestamp_diff = rec.last - act_timestamp;
							}else{
								timestamp_diff = 0;
							}
							if (timestamp_diff >= 1){
								usleep(timestamp_diff * 1000 * 1000); //to convert seconds into microseconds;
								act_timestamp = rec.last;
							}
						}


						if (actual_timestamps){
							time(&act_time);
							first = ur_time_from_sec_msec(act_time - (rec.last - rec.first), rec.msec_first);
							last = ur_time_from_sec_msec(act_time , rec.msec_last);
						}else{
							first = ur_time_from_sec_msec(rec.first, rec.msec_first);
							last = ur_time_from_sec_msec(rec.last, rec.msec_last);
						}
						ur_set(tmplt, rec2, UR_TIME_FIRST, first);
						ur_set(tmplt, rec2, UR_TIME_LAST, last);

						// Send data to output interface
						trap_send_data(0, rec2, ur_rec_static_size(tmplt), COMMONTIMEOUT);
						counter++;
						//usleep(100);

						if (verbose && counter % 1000 == 1) {
							printf(".");
							fflush(stdout);
						}

						if (sending_rate){
							++burst_counter;
						}
					}

					if (sending_rate){
						rec_to_send -= burst_size;
					}
				}

				if (sending_rate){
					usleep(sleeper * 1000);

					++load_index;
					time(&sec);
					if (difftime(next_sec, sec) <= 0){
						time_diff_flag = 0;
					}
				}
			}// for one second

			if (sending_rate){
				if (difftime(sec, next_sec) > 1) {
					burst_size = sending_rate * 2;
					sleeper = 0;
					fprintf(stderr, "Time miss! %f seconds, sending burst of 2x rate.\n", difftime(sec, next_sec));
					time(&sec);
					time(&next_sec);
				}else{
					cmp_index = 10;
					while (load_index > cmp_index) {
						cmp_index *= 10;
					}

					if (load_index < 10){// sending was too slow...
						burst_size *= 4;
						sleeper = 0;
					}else if (cmp_index == 10){// rate was met closely
						burst_size *= 1.5;
						sleeper /= 2;
					}else if (cmp_index == 100){// rate was met - OK
						burst_size /= 1.5;
						sleeper += 5;
					}else{// rate was met, but sending was too fast
						if (burst_size == minimal_burst){
							sleeper = cmp_index / 1000;
						}else{
							burst_size = sending_rate / cmp_index;
						}
					}
					//corrections ...
					if (burst_size < minimal_burst){
						burst_size = minimal_burst;
					}else if (burst_size > sending_rate){
						burst_size = sending_rate;
					}
					if (sleeper > MAX_SLEEP_TIME){
						sleeper = MAX_SLEEP_TIME;
					}
				}
			}//if SENDING RATE MODE
      } // for all records in a file

      if (verbose) {
         printf("done\n");
      }

      nf_close(&file);

   } while (!stop && ++optind < argc); // For all input files

   printf("%lu flow records sent\n", counter);

   // Send data with zero length to signalize end
   char dummy[1] = {0};
   if (!stop && send_eof) { // if EOF enabled and program wasn't interrupted
      if (verbose) {
         printf("Sending EOF message (zero-length record)\n");
      }
      trap_send_data(0, dummy, 1, COMMONTIMEOUT); // FIXME: zero-length messages doesn't work, send message of length 1
   }

   // Do all necessary cleanup before exiting
   ur_free(rec2);
   trap_finalize();

   return 0;
}

