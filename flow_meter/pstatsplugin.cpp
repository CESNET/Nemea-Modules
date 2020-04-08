/**
 * \file pstatsplugin.cpp
 * \brief Plugin for parsing pstats traffic.
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@cesnet.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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
 * This software is provided as is'', and any express or implied
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

#include <iostream>

#include "pstatsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

#define DEBUG_PSTATS

// Print debug message if debugging is allowed.
#ifdef DEBUG_PSTATS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

using namespace std;

#define PSTATS_UNIREC_TEMPLATE "STATS_PCKT_SIZES,STATS_PCKT_DELAYS,STATS_PCKT_TIMESTAMPS,STATS_PCKT_TCPFLGS"

UR_FIELDS (
   uint16* STATS_PCKT_SIZES,
   uint32* STATS_PCKT_DELAYS,
   time* STATS_PCKT_TIMESTAMPS,
   uint8* STATS_PCKT_TCPFLGS
)

PSTATSPlugin::PSTATSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

PSTATSPlugin::PSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

int PSTATSPlugin::pre_create(Packet &pkt)
{
   return 0;
}

void PSTATSPlugin::update_record(RecordExtPSTATS *pstats_data, const Packet &pkt)
{
   if (pstats_data->pkt_count < PSTATS_MAXELEMCOUNT) {
      pstats_data->pkt_sizes[pstats_data->pkt_count] = pkt.ip_length;
      pstats_data->pkt_tcp_flgs[pstats_data->pkt_count] = pkt.tcp_control_bits;

      /* TODO revision needed: */
      if (pstats_data->pkt_count > 0) {
         if (pkt.timestamp.tv_usec < pstats_data->pkt_timestamps[pstats_data->pkt_count - 1].tv_usec) {
            pstats_data->pkt_delays[pstats_data->pkt_count] = pstats_data->pkt_timestamps[pstats_data->pkt_count - 1].tv_usec - pkt.timestamp.tv_usec;
            pstats_data->pkt_delays[pstats_data->pkt_count] += 1000000 * (pkt.timestamp.tv_sec - pstats_data->pkt_timestamps[pstats_data->pkt_count - 1].tv_sec - 1);
         } else {
            pstats_data->pkt_delays[pstats_data->pkt_count] = pkt.timestamp.tv_usec - pstats_data->pkt_timestamps[pstats_data->pkt_count - 1].tv_usec;
            pstats_data->pkt_delays[pstats_data->pkt_count] += 1000000 * (pkt.timestamp.tv_sec - pstats_data->pkt_timestamps[pstats_data->pkt_count - 1].tv_sec);
         }
      } else {
         pstats_data->pkt_delays[pstats_data->pkt_count] = 0;
      }

      pstats_data->pkt_timestamps[pstats_data->pkt_count] = pkt.timestamp;

      DEBUG_MSG("PSTATS processed packet %d: Size: %d Delay: %d Timestamp: %ld.%ld\n", pstats_data->pkt_count,
            pstats_data->pkt_sizes[pstats_data->pkt_count],
            pstats_data->pkt_delays[pstats_data->pkt_count],
            pstats_data->pkt_timestamps[pstats_data->pkt_count].tv_sec,
            pstats_data->pkt_timestamps[pstats_data->pkt_count].tv_usec);

      pstats_data->pkt_count++;
   } else {
      /* Do not count more than PSTATS_MAXELEMCOUNT packets */
   }
}

int PSTATSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtPSTATS *pstats_data = new RecordExtPSTATS();
   rec.addExtension(pstats_data);

   update_record(pstats_data, pkt);
   return 0;
}

int PSTATSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtPSTATS *pstats_data = (RecordExtPSTATS *) rec.getExtension(pstats);
   update_record(pstats_data, pkt);
   return 0;
}

int PSTATSPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void PSTATSPlugin::pre_export(Flow &rec)
{
}

void PSTATSPlugin::finish()
{
   if (print_stats) {
      //cout << "PSTATS plugin stats:" << endl;
   }
}

const char *ipfix_pstats_template[] = {
   IPFIX_PSTATS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **PSTATSPlugin::get_ipfix_string()
{
   return ipfix_pstats_template;
}

string PSTATSPlugin::get_unirec_field_string()
{
   return PSTATS_UNIREC_TEMPLATE;
}

bool PSTATSPlugin::include_basic_flow_fields()
{
   return true;
}