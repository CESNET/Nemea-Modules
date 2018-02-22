/**
 * \file nhtflowcache.cpp
 * \brief "NewHashTable" flow cache
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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

#include <cstdlib>
#include <iostream>
#include <sys/time.h>

#include "nhtflowcache.h"
#include "flowcache.h"
#include "xxhash.h"

using namespace std;

inline __attribute__((always_inline)) bool FlowRecord::is_empty() const
{
   return hash == 0;
}

inline __attribute__((always_inline)) bool FlowRecord::belongs(uint64_t pkt_hash) const
{
   return pkt_hash == hash;
}

void FlowRecord::create(const Packet &pkt, uint64_t pkt_hash)
{
   flow.pkt_total_cnt = 1;

   hash = pkt_hash;

   flow.time_first = pkt.timestamp;
   flow.time_last = pkt.timestamp;

   memcpy(flow.src_mac, pkt.src_mac, 6);
   memcpy(flow.dst_mac, pkt.dst_mac, 6);

   if (pkt.ip_version == 4) {
      flow.ip_version = pkt.ip_version;
      flow.ip_proto = pkt.ip_proto;
      flow.ip_tos = pkt.ip_tos;
      flow.ip_ttl = pkt.ip_ttl;
      flow.src_ip.v4 = pkt.src_ip.v4;
      flow.dst_ip.v4 = pkt.dst_ip.v4;
      flow.octet_total_length = pkt.ip_length;
   } else if (pkt.ip_version == 6) {
      flow.ip_version = pkt.ip_version;
      flow.ip_proto = pkt.ip_proto;
      flow.ip_tos = pkt.ip_tos;
      flow.ip_ttl = pkt.ip_ttl;
      memcpy(flow.src_ip.v6, pkt.src_ip.v6, 16);
      memcpy(flow.dst_ip.v6, pkt.dst_ip.v6, 16);
      flow.octet_total_length = pkt.ip_length;
   }

   if (pkt.field_indicator & PCKT_TCP) {
      flow.src_port = pkt.src_port;
      flow.dst_port = pkt.dst_port;
      flow.tcp_control_bits = pkt.tcp_control_bits;
   } else if (pkt.field_indicator & PCKT_UDP) {
      flow.src_port = pkt.src_port;
      flow.dst_port = pkt.dst_port;
   } else if (pkt.field_indicator & PCKT_ICMP) {
      flow.src_port = pkt.src_port;
      flow.dst_port = pkt.dst_port;
   }
}

void FlowRecord::update(const Packet &pkt)
{
   flow.pkt_total_cnt++;
   flow.time_last = pkt.timestamp;
   flow.octet_total_length += pkt.ip_length;

   if (pkt.field_indicator & PCKT_TCP) {
      flow.tcp_control_bits |= pkt.tcp_control_bits;
   }
}

void NHTFlowCache::init()
{
   plugins_init();
}

void NHTFlowCache::finish()
{
   plugins_finish();

   for (unsigned int i = 0; i < size; i++) {
      if (!flow_array[i]->is_empty()) {
         plugins_pre_export(flow_array[i]->flow);
         exporter->export_flow(flow_array[i]->flow);

         flow_array[i]->erase();
#ifdef FLOW_CACHE_STATS
         expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }

   if (print_stats) {
      print_report();
   }
}

int NHTFlowCache::put_pkt(Packet &pkt)
{
   int ret = plugins_pre_create(pkt);

   if (ret == EXPORT_PACKET) {
      exporter->export_packet(pkt);
      pkt.removeExtensions();
      return 0;
   }

   if (!create_hash_key(pkt)) { // saves key value and key length into attributes NHTFlowCache::key and NHTFlowCache::key_len
      return 0;
   }

   uint64_t hashval = XXH64(key, key_len, 0); /* Calculates hash value from key created before. */

   FlowRecord *flow; /* Pointer to flow we will be working with. */
   bool found = false;
   uint32_t line_index = hashval & line_size_mask; /* Get index of flow line. */
   uint32_t flow_index = 0, next_line = line_index + line_size;

   /* Find existing flow record in flow cache. */
   for (flow_index = line_index; flow_index < next_line; flow_index++) {
      if (flow_array[flow_index]->belongs(hashval)) {
         found = true;
         break;
      }
   }

   if (found) {
      /* Existing flow record was found, put flow record at the first index of flow line. */
#ifdef FLOW_CACHE_STATS
      lookups += (flow_index - line_index + 1);
      lookups2 += (flow_index - line_index + 1) * (flow_index - line_index + 1);
#endif /* FLOW_CACHE_STATS */

      flow = flow_array[flow_index];
      for (uint32_t j = flow_index; j > line_index; j--) {
         flow_array[j] = flow_array[j - 1];
      }

      flow_array[line_index] = flow;
      flow_index = line_index;
#ifdef FLOW_CACHE_STATS
      hits++;
#endif /* FLOW_CACHE_STATS */
   } else {
      /* Existing flow record was not found. Find free place in flow line. */
      for (flow_index = line_index; flow_index < next_line; flow_index++) {
         if (flow_array[flow_index]->is_empty()) {
            found = true;
            break;
         }
      }
      if (!found) {
         /* If free place was not found (flow line is full), find
          * record which will be replaced by new record. */
         flow_index = next_line - 1;

         // Export flow
         plugins_pre_export(flow_array[flow_index]->flow);
         exporter->export_flow(flow_array[flow_index]->flow);

#ifdef FLOW_CACHE_STATS
         expired++;
#endif /* FLOW_CACHE_STATS */
         uint32_t flow_new_index = line_index + 8;
         flow = flow_array[flow_index];
         flow->erase();
         for (uint32_t j = flow_index; j > flow_new_index; j--) {
            flow_array[j] = flow_array[j - 1];
         }
         flow_index = flow_new_index;
         flow_array[flow_new_index] = flow;
#ifdef FLOW_CACHE_STATS
         not_empty++;
      } else {
         empty++;
#endif /* FLOW_CACHE_STATS */
      }
   }

   current_ts = pkt.timestamp;
   flow = flow_array[flow_index];
   if (flow->is_empty()) {
      flow->create(pkt, hashval);
      ret = plugins_post_create(flow->flow, pkt);

      if (ret & FLOW_FLUSH) {
         exporter->export_flow(flow->flow);
#ifdef FLOW_CACHE_STATS
         flushed++;
#endif /* FLOW_CACHE_STATS */
         flow->erase();
      }
   } else {
      ret = plugins_pre_update(flow->flow, pkt);

      if (ret & FLOW_FLUSH) {
         exporter->export_flow(flow->flow);
#ifdef FLOW_CACHE_STATS
         flushed++;
#endif /* FLOW_CACHE_STATS */
         flow->erase();

         return put_pkt(pkt);
      } else {
         flow->update(pkt);
         ret = plugins_post_update(flow->flow, pkt);

         if (ret & FLOW_FLUSH) {
            exporter->export_flow(flow->flow);
#ifdef FLOW_CACHE_STATS
            flushed++;
#endif /* FLOW_CACHE_STATS */
            flow->erase();

            return put_pkt(pkt);
         }
      }

      /* Check if flow record is expired. */
      if (current_ts.tv_sec - flow->flow.time_first.tv_sec >= active.tv_sec) {
         plugins_pre_export(flow->flow);
         exporter->export_flow(flow->flow);
         flow->erase();
#ifdef FLOW_CACHE_STATS
         expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }

   if (current_ts.tv_sec - last_ts.tv_sec > 5) {
      export_expired(current_ts.tv_sec);
      last_ts = current_ts;
   }

   return 0;
}

void NHTFlowCache::export_expired(time_t ts)
{
   for (unsigned int i = 0; i < size; i++) {
      if (!flow_array[i]->is_empty() &&
         ts - flow_array[i]->flow.time_last.tv_sec >= inactive.tv_sec) {

         plugins_pre_export(flow_array[i]->flow);
         exporter->export_flow(flow_array[i]->flow);

         flow_array[i]->erase();
#ifdef FLOW_CACHE_STATS
         expired++;
#endif /* FLOW_CACHE_STATS */
      }
   }
   exporter->flush();
}

bool NHTFlowCache::create_hash_key(Packet &pkt)
{
   if (pkt.ip_version == 4) {
      struct flow_key_v4_t *key_v4 = (struct flow_key_v4_t *) key;

      key_v4->src_port = pkt.src_port;
      key_v4->dst_port = pkt.dst_port;
      key_v4->proto = pkt.ip_proto;
      key_v4->ip_version = 4;
      key_v4->src_ip = pkt.src_ip.v4;
      key_v4->dst_ip = pkt.dst_ip.v4;

      key_len = 14;
      return true;
   } else if (pkt.ip_version == 6) {
      struct flow_key_v6_t *key_v6 = (struct flow_key_v6_t *) key;

      key_v6->src_port = pkt.src_port;
      key_v6->dst_port = pkt.dst_port;
      key_v6->proto = pkt.ip_proto;
      key_v6->ip_version = 6;
      memcpy(key_v6->src_ip, pkt.src_ip.v6, sizeof(pkt.src_ip.v6));
      memcpy(key_v6->dst_ip, pkt.dst_ip.v6, sizeof(pkt.dst_ip.v6));

      key_len = 38;
      return true;
   }

   return false;
}

void NHTFlowCache::print_report()
{
#ifdef FLOW_CACHE_STATS
   float tmp = float(lookups) / hits;

   cout << "Hits: " << hits << endl;
   cout << "Empty: " << empty << endl;
   cout << "Not empty: " << not_empty << endl;
   cout << "Expired: " << expired << endl;
   cout << "Flushed: " << flushed << endl;
   cout << "Average Lookup:  " << tmp << endl;
   cout << "Variance Lookup: " << float(lookups2) / hits - tmp * tmp << endl;
#endif /* FLOW_CACHE_STATS */
}
