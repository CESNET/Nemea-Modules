/**
 * \file nfdump_reader.h
 * \brief Nfdump reader module reads a given nfdump file and outputs flow
 *  records in UniRec format.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>, Pavel Krobot <xkrobo01@cesnet.cz>
 * \date 2013
 */
#define _BSD_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>

#include <unistd.h>
#include <sys/time.h> //gettimeofday for real-time resending

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <libnfdump.h>

#include <real_time_sending.h>

// ***** Defaults and parameters *****
#define DEFAULT_DIR_BIT_FIELD 0
#define DEFAULT_LINK_MASK "1"

#define MINIMAL_SENDING_RATE  100

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
   "   ./nfdump_reader -i IFC_SPEC [-f FILTER] [-c N] [-n] FILE [FILE...]"
   "\n"
   "   FILE   A file in nfdump format.\n"
   "   -f FILTER  A nfdump-like filter expression. Only records matching the filter\n"
   "              will be sent to the output."
   "   -c N   Read only the first N flow records.\n"
   "   -n     Don't send \"EOF message\" at the end.\n"
   "   -T     Replace original timestamps by record actual sending time.\n"
   "   -D     Fill DIR_BIT_FIELD according to record direction.\n"
   "   -l m   Use link mask m for LINK_BIT_FIELD. m is 8-bit hexadecimal number.\n"
   "          e.g. m should be \"1\", \"c2\", \"AB\",...\n"
   "   -r N   Rate limiting. Limiting sending flow rate to N records/sec.\n"
   "   -R     Real time re-sending. Resending records from given files in real\n"
   "          time, respecting original timestamps (seconds). Since this mode\n"
   "          is timestamp order dependent, real time re-sending is done only at\n"
   "          approximate time.\n"
   "",
   0, // Number of input interfaces
   1, // Number of output interfaces
};

static int stop = 0;

enum module_states{
   STATE_OK = 0,
   STATE_ERR = 3
};

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


void set_actual_timestamps(master_record_t *src_rec, void *out_rec, ur_template_t* tmplt){
   time_t act_time;
   uint64_t first;
   uint64_t last;

   time(&act_time);

   first = ur_time_from_sec_msec(act_time - (src_rec->last - src_rec->first), src_rec->msec_first);
   last = ur_time_from_sec_msec(act_time , src_rec->msec_last);

   ur_set(tmplt, out_rec, UR_TIME_FIRST, first);
   ur_set(tmplt, out_rec, UR_TIME_LAST, last);
}

void delay_sending_rate(struct timeval *sr_start){
   struct timeval sr_end;

   gettimeofday(&sr_end, NULL);
   long sr_diff = ((sr_end.tv_sec * 1000000 + sr_end.tv_usec) - (sr_start->tv_sec * 1000000 + sr_start->tv_usec));
   if (sr_diff < 1000000){
      usleep(1000000 - sr_diff);
   }
}

int main(int argc, char **argv)
{
   //------------ General ------------------------------------------------------
   int module_state = STATE_OK;
   int ret;
   int verbose = 0;
   trap_ifc_spec_t ifc_spec;

   int send_eof = 1;
   unsigned long record_counter = 0;
   unsigned long max_records = 0;
   char *filter = NULL;
   uint8_t set_dir_bit_field = 0;
   char *link_mask = DEFAULT_LINK_MASK;// 8*sizeof(char) = 64 bits of uint64_t
   ur_links_t *links;
   //------------ Actual timestamps --------------------------------------------
   int actual_timestamps = 0;
   //------------ Rate limiting ------------------------------------------------
   unsigned long sending_rate = 0;
   struct timeval sr_start;
   //------------ Real-time sendning -------------------------------------------
   uint8_t rt_sending = 0;
   rt_state_t rt_sending_state;
   //---------------------------------------------------------------------------

   // Create UniRec template
   ur_template_t *tmplt = ur_create_template("<COLLECTOR_FLOW>");

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
   while ((opt = getopt(argc, argv, "f:c:nl:Dr:RT")) != -1) {
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
         case 'r':
            sending_rate = atoi(optarg);
            if (sending_rate < MINIMAL_SENDING_RATE) {
               fprintf(stderr, "Invalid sending rate (%i rec/s is minimum).\n", MINIMAL_SENDING_RATE);
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
            return 2;
      }
   }

   if (optind >= argc) {
      fprintf(stderr, "Wrong number of parameters.\nUsage: %s -i trap-ifc-specifier \
            [-f FILTER] [-n] [-c NUM] [-r NUM] [-R] [-T] [-l MASK] [-D] nfdump-file [nfdump-file...]\n", argv[0]);
      return 2;
   }

   links = ur_create_links(link_mask);
   if (links == NULL){
      fprintf(stderr, "Invalid link mask.\n");
      return 2;
   }

   if (sending_rate && rt_sending) {
      fprintf(stderr, "Wrong parameters, use only one of -r / -R.\n");
      return 2;
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

   if (trap_ifcctl(TRAPIFC_OUTPUT, 0,TRAPCTL_BUFFERSWITCH, "0") != TRAP_E_OK){
      fprintf(stderr, "Error while turning off buffering.\n");
   }

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // Allocate memory for output UniRec record (0 bytes for dynamic fields)
   void *rec_out = ur_create(tmplt, 0);

   if (rt_sending){
      RT_INIT(rt_sending_state, 10, 1000, 100, 3.5, goto exit;);
   }

   if (verbose) {
      printf("Sending records ...\n");
   }

   // For all input files...
   do {
      nfdump_iter_t iter;

      // Open nfdump file
      if (verbose) {
         printf("Reading file %s\n", argv[optind]);
      }

      ret = nfdump_iter_start(&iter, argv[optind], filter);
      if (ret != 0) {
         fprintf(stderr, "Error when trying to open file \"%s\"\n", argv[optind]);
         module_state = STATE_ERR;
         goto exit;
      }

      if (sending_rate){
         gettimeofday(&sr_start, NULL);
      }

       // For all records in the file...
      while (!stop && (max_records == 0 || record_counter < max_records)) {
         master_record_t *src_rec;

         // Read a record from the file
         ret = nfdump_iter_next(&iter, &src_rec);
         if (ret != 0) {
            if (ret == NFDUMP_EOF) { // no more records
               break;
            }
            fprintf(stderr, "Error during reading file (%i).\n", ret);
            nfdump_iter_end(&iter);
            module_state = STATE_ERR;
            goto exit;
         }

         // Copy data from master_record_t to UniRec record
         if (src_rec->flags & 0x01) { // IPv6
            uint64_t tmp_ip_v6_addr;
            // Swap IPv6 halves
            tmp_ip_v6_addr = src_rec->ip_union._v6.srcaddr[0];
            src_rec->ip_union._v6.srcaddr[0] = src_rec->ip_union._v6.srcaddr[1];
            src_rec->ip_union._v6.srcaddr[1] = tmp_ip_v6_addr;
            tmp_ip_v6_addr = src_rec->ip_union._v6.dstaddr[0];
            src_rec->ip_union._v6.dstaddr[0] = src_rec->ip_union._v6.dstaddr[1];
            src_rec->ip_union._v6.dstaddr[1] = tmp_ip_v6_addr;
            ur_set(tmplt, rec_out, UR_SRC_IP, ip_from_16_bytes_le((char *)src_rec->ip_union._v6.srcaddr));
            ur_set(tmplt, rec_out, UR_DST_IP, ip_from_16_bytes_le((char *)src_rec->ip_union._v6.dstaddr));
         } else { // IPv4
            ur_set(tmplt, rec_out, UR_SRC_IP, ip_from_4_bytes_le((char *)&src_rec->ip_union._v4.srcaddr));
            ur_set(tmplt, rec_out, UR_DST_IP, ip_from_4_bytes_le((char *)&src_rec->ip_union._v4.dstaddr));
         }
//            printf("%i \n", (void *)&src_rec->input - (void *)&src_rec);
         ur_set(tmplt, rec_out, UR_SRC_PORT, src_rec->srcport);
         ur_set(tmplt, rec_out, UR_DST_PORT, src_rec->dstport);
         ur_set(tmplt, rec_out, UR_PROTOCOL, src_rec->prot);
         ur_set(tmplt, rec_out, UR_TCP_FLAGS, src_rec->tcp_flags);
         ur_set(tmplt, rec_out, UR_PACKETS, src_rec->dPkts);
         ur_set(tmplt, rec_out, UR_BYTES, src_rec->dOctets);
         ur_set(tmplt, rec_out, UR_LINK_BIT_FIELD, ur_get_link_mask(links));
         if (set_dir_bit_field){
            if (src_rec->input > 0){
               ur_set(tmplt, rec_out, UR_DIR_BIT_FIELD, (1 << src_rec->input));
            } else {
               ur_set(tmplt, rec_out, UR_DIR_BIT_FIELD, DEFAULT_DIR_BIT_FIELD);
            }
         } else {
            ur_set(tmplt, rec_out, UR_DIR_BIT_FIELD, DEFAULT_DIR_BIT_FIELD);
         }
         ur_set(tmplt, rec_out, UR_TIME_FIRST, ur_time_from_sec_msec(src_rec->first, src_rec->msec_first));
         ur_set(tmplt, rec_out, UR_TIME_LAST, ur_time_from_sec_msec(src_rec->last, src_rec->msec_last));

         if (rt_sending){
            RT_CHECK_DELAY(record_counter, src_rec->last, rt_sending_state);
         }

         if (actual_timestamps){
            set_actual_timestamps(src_rec, rec_out, tmplt);
         }

         // Send data to output interface
         trap_send(0, rec_out, ur_rec_static_size(tmplt));
         record_counter++;

         if (sending_rate){
            if ((record_counter % sending_rate) == 0){
               delay_sending_rate(&sr_start);
               gettimeofday(&sr_start, NULL);
            }
         }

         if (verbose && record_counter % 1000 == 1) {
            printf(".");
            fflush(stdout);
         }

      }// for all records in a file
      if (verbose) {
         printf("done.\n");
      }
      nfdump_iter_end(&iter);
   } while (!stop && ++optind < argc); // For all input files

   printf("%lu flow records sent\n", record_counter);

   // Send data with zero length to signalize end
   char dummy[1] = {0};
   if (!stop && send_eof) { // if EOF enabled and program wasn't interrupted
      if (verbose) {
         printf("Sending EOF message (zero-length record)\n");
      }
      trap_send(0, dummy, 1); // FIXME: zero-length messages doesn't work, send message of length 1
   }

exit:
   if (rt_sending){
      RT_DESTROY(rt_sending_state);
   }
   trap_finalize();
   ur_free(rec_out);
   ur_free_template(tmplt);
   ur_free_links(links);

   return module_state;
}
