/**
 * \file natpair.h
 * \brief Module for pairing flows which undergone Network address translation (NAT) process.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2013,2014,2015,2016 CESNET
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <iostream>
#include <cstdlib>

using namespace std;

#define VERBOSE(...) if (verbose >= 0) { \
   printf(__VA_ARGS__); \
}

#define UNIREC_INPUT_TEMPLATE "DST_IP,SRC_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST"
#define UNIREC_OUTPUT_TEMPLATE "DST_IP,SRC_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST"
#define THREAD_CNT 2

#define IP_P_1_START 167772160   // 10.0.0.0
#define IP_P_1_END   184549375   // 10.255.255.255
#define IP_P_2_START 2886729728  // 172.16.0.0
#define IP_P_2_END   2887778303  // 172.31.255.255
#define IP_P_3_START 3232235520  // 192.168.0.0
#define IP_P_3_END   3232301055  // 192.168.255.255

#define DEFAULT_CHECK_TIME 600000
#define DEFAULT_FREE_TIME  5000
#define DEFAULT_CACHE_SIZE 2000

enum nat_direction_t {
   LANtoWAN = 0,
   WANtoLAN,
   NONE
};

enum net_scope_t {
   LAN = 0,
   WAN
};

class Flow {
public:
   Flow();
   Flow(const Flow &other);
   Flow& operator=(const Flow &other);
   bool operator==(const Flow &other) const;
   bool prepare(const ur_template_t *tmplt, const void *rec, net_scope_t sc);
   uint64_t hashKey() const;
   void complete(const Flow &other);
   ur_time_t getTime() const;
   net_scope_t getScope() const;

   friend ostream& operator<<(ostream& str, const Flow &other);
private:
   void setDirection(uint32_t src_ip, uint32_t dst_ip);
   void adjustDirection(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);

   uint32_t lan_ip;
   uint32_t wan_ip;
   uint16_t lan_port;
   uint16_t router_port;
   uint16_t wan_port;
   ur_time_t lan_time_first;
   ur_time_t lan_time_last;
   ur_time_t wan_time_first;
   ur_time_t wan_time_last;
   uint8_t protocol;
   uint8_t direction;
   net_scope_t scope;
};
