/**
 * \file ipv6stats.cpp
 * \brief Nemea module for gathering IPv6 (mainly) statistics.
 * \author Pavel Krobot <xkrobo01@cesnet.cz>
 * \date 2014 - 2017
 */

/*
 * Copyright (C) 2014 - 2017 CESNET
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

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <string>
#include <unistd.h>
#include <getopt.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include "ipv6stats.h"
#include <BloomFilter.hpp>


#include <iomanip>

using namespace std;

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
   uint8 TTL,
   uint8 IPV6_TUN_TYPE
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("IPv6 Statistics module","Module for calculating various IPv6 statistics.",1,0)

#define MODULE_PARAMS(PARAM) \
  PARAM('d', "dir", "Path to output files (have to be ended by /, default /).", required_argument, "string") \
  PARAM('l', "length_long", "Length of long window (in seconds, for better performance should be multiple of short window size).", required_argument, "int32") \
  PARAM('L', "length_multi", "Set length of long window by multiple of small window (default 12).", required_argument, "int32") \
  PARAM('n', "no_last", "For not printing statistics from last (incomplete) window. Last window statistics print by default.", no_argument, "none") \
  PARAM('p', "packets", "Number of packets, which elemet have to sent to include it in unique statistics (default 1).", required_argument, "int32") \
  PARAM('s', "length_small", "Length of small window (in seconds, default 300).", required_argument, "int32")

static int stop = 0;

static uint32_t actual_time;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

/**
 * Clear a structure for a statistics
 *
 * @param [in,out] stats   Pointer to structure with statistics.
 * @param [in] stats_type  Type of statistics (short/long).
 */
void clear_stats (stats_t *stats, int stats_type)
{
   // not affecting stored time
   if (stats_type == STSHORT){
      memset(stats->ipv4cnt, 0, sizeof(stats->ipv4cnt[0]) * 3);
      memset(stats->ipv6cnt, 0, sizeof(stats->ipv6cnt[0]) * 3);
      memset(stats->tunnel_cnt, 0, sizeof(stats->tunnel_cnt[0][0]) * TUNNEL_TYPE_COUNT * 3);
   }

   stats->uni_ipv4[stats_type] = 0;
   stats->uni_ipv6[stats_type] = 0;
   stats->uni_prefix64[stats_type] = 0;
   stats->uni_prefix48[stats_type] = 0;
}

/**
 * Write short/long window statistics to a file.
 *
 * @param [in] stats        Pointer to structure with statistics.
 * @param [in] stats_type   Which statistics will be flushed (short/long).
 * @param [in] window_size  Size of window (short/long) for counting bit/packet/flow rate.
 * @param [in] path         Path to output data.
 */
void flush_stats(stats_t *stats, int stats_type, int window_size, const char* path, bool flush_by_inactive)
{
   ostringstream filename;
   ofstream out_file;

   time_t now = time(NULL);
   tm * ptm = localtime(&now);
   char buffer[32];
   strftime(buffer, 32, "%Y-%m-%d.%H:%M:%S", ptm);

   filename.str("");
   filename.clear();
   filename << path << FILENAME_ADDR;
   if (stats_type == STLONG){
      filename << FN_SUFFIX_LONG_WINDOW;
   }
   out_file.open(filename.str().c_str());
   if (out_file.is_open()) {
      out_file << "ipv4" << COL_DELIM << stats->uni_ipv4[stats_type] << "\n";
      out_file << "ipv6" << COL_DELIM << stats->uni_ipv6[stats_type] << "\n";
      out_file << "ipv6_48" << COL_DELIM << stats->uni_prefix48[stats_type] << "\n";
      out_file << "ipv6_64" << COL_DELIM << stats->uni_prefix64[stats_type] << "\n";
      out_file << "updated " << buffer << endl;
      if (flush_by_inactive){
         out_file << "INACTIVE" << endl;
      }
      out_file.close();
   } else {
      cerr << "Warning: Unable to open output file " << filename.str() << ". ";
      cerr << "Skipping (" << buffer << ").";
   }

   if (stats_type == STSHORT){
      filename.str("");
      filename.clear();
      filename << path << FILENAME_TRAFFIC;
      out_file.open(filename.str().c_str());
      if (out_file.is_open()) {
         out_file << fixed << setprecision(3) << "ipv4" << COL_DELIM << (float) stats->ipv4cnt[CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->ipv4cnt[CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->ipv4cnt[CIFLOW]/window_size << "\n";
         out_file << "ipv6" << COL_DELIM << (float) stats->ipv6cnt[CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->ipv6cnt[CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->ipv6cnt[CIFLOW]/window_size << "\n";
         out_file << "updated " << buffer << endl;
         if (flush_by_inactive){
            out_file << "INACTIVE" << endl;
         }
         out_file.close();
      } else {
         cerr << "Warning: Unable to open output file " << filename.str() << ". ";
         cerr << "Skipping (" << buffer << ").";
      }

      filename.str("");
      filename.clear();
      filename << path << FILENAME_TUNNELS;
      out_file.open(filename.str().c_str());
      if (out_file.is_open()) {
         out_file << "Native" << COL_DELIM << (float) stats->tunnel_cnt[TTNATIVE][CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->tunnel_cnt[TTNATIVE][CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->tunnel_cnt[TTNATIVE][CIFLOW]/window_size << "\n";
         out_file << "Teredo" << COL_DELIM << (float) stats->tunnel_cnt[TTTEREDO][CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->tunnel_cnt[TTTEREDO][CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->tunnel_cnt[TTTEREDO][CIFLOW]/window_size << "\n";
         out_file << "ISATAP" << COL_DELIM << (float) stats->tunnel_cnt[TTISATAP][CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->tunnel_cnt[TTISATAP][CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->tunnel_cnt[TTISATAP][CIFLOW]/window_size << "\n";
         out_file << "6to4" << COL_DELIM << (float) stats->tunnel_cnt[TT6TO4][CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->tunnel_cnt[TT6TO4][CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->tunnel_cnt[TT6TO4][CIFLOW]/window_size << "\n";
         out_file << "AYIYA" << COL_DELIM << (float) stats->tunnel_cnt[TTAYIYA][CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->tunnel_cnt[TTAYIYA][CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->tunnel_cnt[TTAYIYA][CIFLOW]/window_size << "\n";
         out_file << "Proto41" << COL_DELIM << (float) stats->tunnel_cnt[TTPROTO41][CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->tunnel_cnt[TTPROTO41][CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->tunnel_cnt[TTPROTO41][CIFLOW]/window_size << "\n";
         out_file << "6over4" << COL_DELIM << (float) stats->tunnel_cnt[TT6TO4][CIPACKET]/window_size;
         out_file << COL_DELIM << (float) (stats->tunnel_cnt[TT6TO4][CIBYTE]*8)/window_size;
         out_file << COL_DELIM << (float) stats->tunnel_cnt[TT6TO4][CIFLOW]/window_size << "\n";
         out_file << "updated " << buffer << endl;
         if (flush_by_inactive){
            out_file << "INACTIVE" << endl;
         }
         out_file.close();
      } else {
         cerr << "Warning: Unable to open output file " << filename.str() << ". ";
         cerr << "Skipping (" << buffer << ").";
      }
   }
}

/**
 * Main function.
 *
 * @param argc
 * @param argv
 */
int main (int argc, char** argv) {
   // ***** Declarations *****
   int ret;
   int init_flag = 1;
   //settings
   string output_path = DEFAULT_OUTPUT_PATH;
   int window_short = DEFAULT_WINDOW_SHORT;
   int window_long = DEFAULT_WINDOW_LONG;
   int window_long_multiplier = 0;
   uint32_t packet_cnt_threshold = DEFAULT_PACKET_CNT_THRESHOLD;
   int flush_on_exit = DEFAULT_FLUSH_ON_EXIT;
   //record info
   uint8_t tunnel_type;
   int tunnel_id;
   uint32_t act_packets;
   uint64_t act_bytes;

   bool inactive = false;

   bloom_parameters bp;
   bloom_filter *bf_ipv4_short;
   bloom_filter *bf_ipv4_long;
   bloom_filter *bf_ipv6_short;
   bloom_filter *bf_ipv6_long;
   bloom_filter *bf_pref64_short;
   bloom_filter *bf_pref64_long;
   bloom_filter *bf_pref48_short;
   bloom_filter *bf_pref48_long;
   bool present;
   stats_t stats;

   memset(&stats, 0, sizeof(stats_t));

   // initialize TRAP interface
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   // set signal handling for termination
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Parse parameters *****
   char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'd':
            output_path = optarg;
            break;
         case 'n':
            flush_on_exit = 0;
            break;
         case 'l':
            window_long = atoi(optarg);
            break;
         case 'L':
            window_long_multiplier = atoi(optarg);
            break;
         case 'p':
            packet_cnt_threshold = atoi(optarg);
            break;
         case 's':
            window_short = atoi(optarg);
            break;
         default:
            cerr << "Error: Invalid arguments." << endl;
            trap_finalize();
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return EPARAM;
      }
   }
   // value check
   if (window_short < 1 || window_long < 1){
      cerr << "Error: Bad window size." << endl;
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return EPARAM;
   }

   if (window_long_multiplier) { // default window_long_multiplier = 0
      window_long = window_short * window_long_multiplier;
   }

   // declare demplate
   ur_template_t *in_tmplt = ur_create_input_template(0 ,"SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL,IPV6_TUN_TYPE", NULL);

   // check created templates
   if (in_tmplt == NULL) {
      cerr << "Error: Invalid UniRec specifier." << endl;
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return EUNIREC;
   }

   //Create bloom filters
   bp.false_positive_probability = FALSE_POS_PROB;

   bp.projected_element_count = CNT_IPV4_SHORT;
   bp.compute_optimal_parameters();
   bf_ipv4_short = new bloom_filter(bp);

   bp.projected_element_count = CNT_IPV4_LONG;
   bp.compute_optimal_parameters();
   bf_ipv4_long = new bloom_filter(bp);

   bp.projected_element_count = CNT_IPV6_SHORT;
   bp.compute_optimal_parameters();
   bf_ipv6_short = new bloom_filter(bp);

   bp.projected_element_count = CNT_IPV6_LONG;
   bp.compute_optimal_parameters();
   bf_ipv6_long = new bloom_filter(bp);

   bp.projected_element_count = CNT_PREF64_SHORT;
   bp.compute_optimal_parameters();
   bf_pref64_short = new bloom_filter(bp);

   bp.projected_element_count = CNT_PREF64_LONG;
   bp.compute_optimal_parameters();
   bf_pref64_long = new bloom_filter(bp);

   bp.projected_element_count = CNT_PREF48_SHORT;
   bp.compute_optimal_parameters();
   bf_pref48_short = new bloom_filter(bp);

   bp.projected_element_count = CNT_PREF48_LONG;
   bp.compute_optimal_parameters();
   bf_pref48_long = new bloom_filter(bp);

   // data buffer
   const void *rec;
   uint16_t rec_size;

   trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, MY_TRAP_TIMEOUT);

   clear_stats(&stats, STSHORT);
   clear_stats(&stats, STLONG);

   // ***** Main processing loop *****
   while (!stop) {
      // retrieve data from server
      ret = TRAP_RECEIVE(0, rec, rec_size, in_tmplt);
      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_TERMINATED) {
            break; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
         } else if (ret == TRAP_E_TIMEOUT) {
            if (!inactive){
               time_t now = time(NULL);
               tm * ptm = localtime(&now);
               char buffer[32];
               strftime(buffer, 32, "%Y-%m-%d.%H:%M:%S", ptm);

               cerr << buffer << ", Error: timeout reached on input interface. Flushing by inactive." << endl;
               flush_stats(&stats, STSHORT, window_short, output_path.c_str(), true);
               clear_stats(&stats, STSHORT);
               bf_ipv4_short->clear();
               bf_ipv6_short->clear();
               bf_pref64_short->clear();
               bf_pref48_short->clear();

               stats.end_of_window[STSHORT] += window_short;
               flush_stats(&stats, STLONG, window_long, output_path.c_str(), true);
               clear_stats(&stats, STLONG);
               bf_ipv4_long->clear();
               bf_ipv6_long->clear();
               bf_pref64_long->clear();
               bf_pref48_long->clear();

               stats.end_of_window[STLONG] += window_long;
               trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, window_short * 1000000);//wait one short window
               inactive = true;
            } else {//after one short window, wirte zeros and wait on src data
               time_t now = time(NULL);
               tm * ptm = localtime(&now);
               char buffer[32];
               strftime(buffer, 32, "%Y-%m-%d.%H:%M:%S", ptm);

               cerr << buffer << ", Error: timeout reached on input interface. No data since last timeout." << endl;
               flush_stats(&stats, STSHORT, window_short, output_path.c_str(), true);
               clear_stats(&stats, STSHORT);

               stats.end_of_window[STSHORT] += window_short;
               flush_stats(&stats, STLONG, window_long, output_path.c_str(), true);
               clear_stats(&stats, STLONG);

               stats.end_of_window[STLONG] += window_long;
               trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_WAIT);
            }
            continue;
         } else {
            cerr << "Error: trap_recv() returned " << ret << " (" << trap_last_error_msg << ")" << endl;
            continue;
         }
      }

      if (inactive){
         trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, MY_TRAP_TIMEOUT);
         inactive = false;
      }

      // check the data size
      if ((rec_size != ur_rec_fixlen_size(in_tmplt))) {
         if (rec_size <= 1) { // end of data
            break;
         } else { // data corrupted
            cerr << "Error: Wrong data size. Expected: " << ur_rec_fixlen_size(in_tmplt);
            cerr << ", recieved: " << rec_size << "." << endl;
            break;
         }
      }
      // get timestamp of record
      actual_time = ur_time_get_sec(ur_get(in_tmplt, rec, F_TIME_LAST));

      // init counters
      if (init_flag) {
         init_flag = 0;
         stats.end_of_window[STSHORT] = get_closest_window_end(actual_time, window_short);
         stats.end_of_window[STLONG] = get_closest_window_end(actual_time, window_long);

         clear_stats(&stats, STSHORT);
         clear_stats(&stats, STLONG);
      }

      // end of short window check
      if (actual_time >= stats.end_of_window[STSHORT]){
         flush_stats(&stats, STSHORT, window_short, output_path.c_str(), false);
         clear_stats(&stats, STSHORT);
         bf_ipv4_short->clear();
         bf_ipv6_short->clear();
         bf_pref64_short->clear();
         bf_pref48_short->clear();

         stats.end_of_window[STSHORT] += window_short;
      }
      // end of long window check
      if (actual_time >= stats.end_of_window[STLONG]){
         flush_stats(&stats, STLONG, window_long, output_path.c_str(), false);
         clear_stats(&stats, STLONG);
         bf_ipv4_long->clear();
         bf_ipv6_long->clear();
         bf_pref64_long->clear();
         bf_pref48_long->clear();

         stats.end_of_window[STLONG] += window_long;
      }

      // get required info from record
      act_packets = ur_get(in_tmplt, rec, F_PACKETS);
      act_bytes = ur_get(in_tmplt, rec, F_BYTES);
      tunnel_type = ur_get(in_tmplt, rec, F_IPV6_TUN_TYPE);
      // determine tunnel type/id
      tunnel_id=0;
      while (tunnel_type && tunnel_id < TUNNEL_TYPE_COUNT){
         ++tunnel_id;
         tunnel_type >>= 1;
      }// tunnel_type overflow if to 0 if tunnel is not used


      // IPv4/v6 statistics
      if (ip_is4(ur_get_ptr(in_tmplt, rec, F_SRC_IP))){//IPv4
         stats.ipv4cnt[CIFLOW]++;
         stats.ipv4cnt[CIPACKET] += act_packets;
         stats.ipv4cnt[CIBYTE] += act_bytes;

         if (tunnel_id > 0){ // 0 = no tunnel (or native ipv6...)
            // store tunnel statistics
            stats.tunnel_cnt[tunnel_id][CIFLOW]++;
            stats.tunnel_cnt[tunnel_id][CIPACKET] += act_packets;
            stats.tunnel_cnt[tunnel_id][CIBYTE] += act_bytes;
         }

         if (act_packets >= packet_cnt_threshold){
            // unique v4 address statistics
            uint32_t addr_int = ip_get_v4_as_int(ur_get_ptr(in_tmplt, rec, F_SRC_IP));

            present = false;
            present = bf_ipv4_long->containsinsert((const unsigned char *) &addr_int, sizeof(addr_int));
            if (present) {// is in long stats -> ?? in short stats ??
               present = false;
               present = bf_ipv4_short->containsinsert((const unsigned char *) &addr_int, sizeof(addr_int));
               if (!present) {
                  stats.uni_ipv4[STSHORT]++;
               }
            } else { //not in long stats -> not in short stats
               stats.uni_ipv4[STLONG]++;

               bf_ipv4_short->insert((const unsigned char *) &addr_int, sizeof(addr_int));
               stats.uni_ipv4[STSHORT]++;
            }
         }// if threshold

      } else {// IPv6
         stats.ipv6cnt[CIFLOW]++;
         stats.ipv6cnt[CIPACKET] += act_packets;
         stats.ipv6cnt[CIBYTE] += act_bytes;

         // store tunnel statistics
         stats.tunnel_cnt[TTNATIVE][CIFLOW]++;
         stats.tunnel_cnt[TTNATIVE][CIPACKET] += act_packets;
         stats.tunnel_cnt[TTNATIVE][CIBYTE] += act_bytes;

         if (act_packets >= packet_cnt_threshold){
            ip_addr_t addr = ur_get(in_tmplt, rec, F_SRC_IP);

            present = false;
            present = bf_ipv6_short->containsinsert((const unsigned char *) &addr.ui64[0], sizeof(addr.ui64[0])*2);
            if (!present) { // not in ipv6 short -> ?? in pref64 / pref48 short ??
               stats.uni_ipv6[STSHORT]++;

               present = bf_pref64_short->containsinsert((const unsigned char *) &addr.ui64[0], sizeof(addr.ui64[0]));
               if (!present) { // not in pref64 short -> ?? in pref48 short ??
                  stats.uni_prefix64[STSHORT]++;

                  present = false;
                  present = bf_pref48_short->containsinsert((const unsigned char *) &addr.ui64[0] , 6); // 6 as 48/8 for prefix48
                  if (!present) {
                     stats.uni_prefix48[STSHORT]++;
                  }// is in pref64 -> is in pref48
               }// is in pref48
            }// is in ipv6 short -> in pref48 / pref64 short

            present = false;
            present = bf_ipv6_long->containsinsert((const unsigned char *) &addr.ui64[0], sizeof(addr.ui64[0])*2);
            if (!present) { // not in ipv6 long -> ?? in pref64 / pref48 long ??
               stats.uni_ipv6[STLONG]++;

               present = bf_pref64_long->containsinsert((const unsigned char *) &addr.ui64[0], sizeof(addr.ui64[0]));
               if (!present) { // not in pref64 long -> ?? in pref48 long ??
                  stats.uni_prefix64[STLONG]++;

                  present = false;
                  present = bf_pref48_long->containsinsert((const unsigned char *) &addr.ui64[0] , 6); // 6 as 48/8 for prefix48
                  if (!present) {
                     stats.uni_prefix48[STLONG]++;
                  }// is in pref64 -> is in pref48
               }// is in pref48
            }// is in ipv6 long -> in pref48 / pref64 long
         } // if threshold
      }
   }

   // ***** Flush statistics on exit *****
   if (flush_on_exit){
      flush_stats(&stats, STSHORT, window_short, output_path.c_str(), false);
      flush_stats(&stats, STLONG, window_short, output_path.c_str(), false);
   }

   cerr << "Cleaning up." << endl;

   // ***** Clean up *****
   delete bf_ipv4_short;
   delete bf_ipv4_long;
   delete bf_ipv6_short;
   delete bf_ipv6_long;
   delete bf_pref64_short;
   delete bf_pref64_long;
   delete bf_pref48_short;
   delete bf_pref48_long;

   ur_free_template(in_tmplt);
   trap_finalize();
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   cerr << "Exiting normally." << endl;

   return EOK;
}
//END of ipv6stats.cpp
