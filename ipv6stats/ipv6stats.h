/**
 * \file ipv6stats.h
 * \brief Nemea module for gathering IPv6 statistics (header file).
 * \author Pavel Krobot <xkrobo01@cesnet.cz>
 * \date 3/2014
 */

/*
 * Copyright (C) 2014 CESNET
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

#ifndef NEMEA_IPV6_STATS
#define NEMEA_IPV6_STATS

// Limit for bad input records  (exit after limit is reached)
#define BAD_SIZE_RECORD_LIMIT 100 // 0 = unlimited
#define NO_DATA_LIMIT         0 // 0 = unlimited

// Default settings
#define DEFAULT_OUTPUT_PATH            ""
#define DEFAULT_OUTPUT_PATH_MUNIN      "/var/spool/nfmunin/"
#define DEFAULT_WINDOW_SHORT           300 // in seconds
#define DEFAULT_WINDOW_LONG            (DEFAULT_WINDOW_SHORT*12) // in seconds
#define DEFAULT_PACKET_CNT_THRESHOLD   1 // number of packet (>= <value>)
#define DEFAULT_FLUSH_ON_EXIT          1 // >=1 - YES / =0 - NO

// Count of type of tunnels
#define TUNNEL_TYPE_COUNT 7

// Output settings
#define FILENAME_TRAFFIC "traffic"
#define FILENAME_ADDR    "cnt_addr"
#define FILENAME_TUNNELS "ipv6_tunnels"
#define FN_SUFFIX_LONG_WINDOW "_L"

#define COL_DELIM " "

#define INPUT_TRAP_TIMEOUT 10000000//in microseondcs - 10 seconds
#define INACTIVE_FLUSH_TIME_TOLERANCE 11 // in seconds

#define PREFIX48_MASK   0xFFFFFFFFFFFF0000

// Bloom filter settings
#define FALSE_POS_PROB     0.0001
#define CNT_IPV4_SHORT     6000000
#define CNT_IPV4_LONG      40000000
#define CNT_IPV6_SHORT     100000
#define CNT_IPV6_LONG      500000
#define CNT_PREF64_SHORT   50000
#define CNT_PREF64_LONG    250000
#define CNT_PREF48_SHORT   30000
#define CNT_PREF48_LONG    150000

#define MY_TRAP_TIMEOUT    40000000 // 40 seconds

using namespace std;

enum error_codes
{
  EOK=0,
  EPARAM,
  EUNIREC,
  EUNKNOWN
};

enum cnt_indexes
{
  CIFLOW=0,
  CIPACKET,
  CIBYTE
};

enum stat_type
{
  STSHORT=0,
  STLONG
};

enum tunnel_types
{
   TTNATIVE=0,
   TTTEREDO,
   TTISATAP,
   TT6TO4,
   TTAYIYA,
   TTPROTO41,
   TT6OVER4
};

/**
 * \brief Structure for storing a statistics (both, short and log window).
 */
typedef struct stats_s{
   uint32_t end_of_window[2];
   uint64_t ipv4cnt [3];
   uint64_t ipv6cnt [3];
   uint64_t tunnel_cnt [TUNNEL_TYPE_COUNT][3];
   uint64_t uni_ipv4[2];
   uint64_t uni_ipv6[2];
   uint64_t uni_prefix64[2];
   uint64_t uni_prefix48[2];
}stats_t;

/**
 * \brief Returns timestamp, rounded to the closest window end.
 * \param [in] timestamp    Actual timestamp.
 * \param [in] window_size  Size of window.
 * \return The closest rounded window end.
 */
INLINE uint32_t get_closest_window_end(uint32_t timestamp, uint32_t window_size)
{
   return (timestamp + (window_size - (timestamp % window_size)));
}

#endif /* NEMEA_IPV6_STATS */
//END of ipv6stats.h
