/**
 * \file pstatsplugin.h
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

#ifndef PSTATSPLUGIN_H
#define PSTATSPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

#ifndef PSTATS_MAXELEMCOUNT
#define PSTATS_MAXELEMCOUNT 20
#endif

using namespace std;

/**
 * \brief Flow record extension header for storing parsed PSTATS packets.
 */
struct RecordExtPSTATS : RecordExt {
   uint16_t pkt_sizes[PSTATS_MAXELEMCOUNT];
   uint32_t pkt_delays[PSTATS_MAXELEMCOUNT];
   struct timeval pkt_timestamps[PSTATS_MAXELEMCOUNT];
   uint8_t pkt_count;

   RecordExtPSTATS() : RecordExt(pstats)
   {
      memset(pkt_sizes, 0, PSTATS_MAXELEMCOUNT * sizeof(pkt_sizes[0]));
      memset(pkt_delays, 0, PSTATS_MAXELEMCOUNT * sizeof(pkt_delays[0]));
      memset(pkt_timestamps, 0, PSTATS_MAXELEMCOUNT * sizeof(pkt_timestamps[0]));
      pkt_count = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_array_resize(tmplt, record, F_STATS_PCKT_TIMESTAMPS, pkt_count);
      ur_array_resize(tmplt, record, F_STATS_PCKT_DELAYS, pkt_count);
      ur_array_resize(tmplt, record, F_STATS_PCKT_SIZES, pkt_count);
      for (uint8_t i = 0; i < pkt_count; i++) {
         ur_time_t ts = ur_time_from_sec_usec(pkt_timestamps[i].tv_sec, pkt_timestamps[i].tv_usec);
         ur_array_set(tmplt, record, F_STATS_PCKT_TIMESTAMPS, i, ts);
         ur_array_set(tmplt, record, F_STATS_PCKT_DELAYS, i, pkt_delays[i]);
         ur_array_set(tmplt, record, F_STATS_PCKT_SIZES, i, pkt_sizes[i]);
      }
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      /* TODO */
      return 0;
   }
};

/**
 * \brief Flow cache plugin for parsing PSTATS packets.
 */
class PSTATSPlugin : public FlowCachePlugin
{
public:
   PSTATSPlugin(const options_t &module_options);
   PSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void update_record(RecordExtPSTATS *pstats_data, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif

