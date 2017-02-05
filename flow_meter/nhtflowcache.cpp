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
#include <nemea-common.h>

#include "nhtflowcache.h"
#include "flowcache.h"

using namespace std;

/**
 * \brief Check whether flow is expired or not.
 * \param [in] flow Pointer to flow.
 * \param [in] current_ts Current timestamp.
 * \param [in] active Active timeout.
 * \param [in] inactive Inactive timeout.
 * \return True if flow is expired, false otherwise.
 */
inline bool is_expired(const FlowRecord *flow_rec, const struct timeval &current_ts,
                       const struct timeval &active, const struct timeval &inactive)
{
   if (!flow_rec->is_empty() && current_ts.tv_sec - flow_rec->flow.time_last.tv_sec >= inactive.tv_sec) {
      return true;
   } else {
      return false;
   }
}

inline bool FlowRecord::is_empty() const
{
   return empty_flow;
}

bool FlowRecord::belongs(uint64_t pkt_hash, char *pkt_key, uint8_t key_len) const
{
   if (is_empty() || (pkt_hash != hash)) {
      return false;
   } else {
      return (memcmp(key, pkt_key, key_len) == 0);
   }
}

void FlowRecord::create(const Packet &pkt, uint64_t pkt_hash, char *pkt_key, uint8_t key_len)
{
   flow.field_indicator    = FLW_FLOWFIELDINDICATOR;
   flow.pkt_total_cnt      = 1;
   flow.field_indicator   |= FLW_PACKETTOTALCOUNT;

   hash = pkt_hash;
   memcpy(key, pkt_key, key_len);

   if ((pkt.field_indicator & PCKT_INFO_MASK) == PCKT_INFO_MASK) {
      flow.field_indicator |= FLW_HASH;
   }

   if ((pkt.field_indicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK) {
      flow.time_first               = pkt.timestamp;
      flow.time_last                = pkt.timestamp;
      flow.field_indicator         |= FLW_TIMESTAMPS_MASK;
   }

   if ((pkt.field_indicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      flow.ip_version               = pkt.ip_version;
      flow.ip_proto                 = pkt.ip_proto;
      flow.ip_tos                   = pkt.ip_tos;
      flow.ip_ttl                   = pkt.ip_ttl;
      flow.src_ip.v4                = pkt.src_ip.v4;
      flow.dst_ip.v4                = pkt.dst_ip.v4;
      flow.octet_total_length       = pkt.ip_length;
      flow.field_indicator         |= (FLW_IPV4_MASK | FLW_IPSTAT_MASK);
   } else if ((pkt.field_indicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      flow.ip_version               = pkt.ip_version;
      flow.ip_proto                 = pkt.ip_proto;
      flow.ip_tos                   = pkt.ip_tos;
      memcpy(flow.src_ip.v6, pkt.src_ip.v6, 16);
      memcpy(flow.dst_ip.v6, pkt.dst_ip.v6, 16);
      flow.octet_total_length         = pkt.ip_length;
      flow.field_indicator           |= (FLW_IPV6_MASK | FLW_IPSTAT_MASK);
   }

   if ((pkt.field_indicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) {
      flow.src_port                  = pkt.src_port;
      flow.dst_port                  = pkt.dst_port;
      flow.tcp_control_bits          = pkt.tcp_control_bits;
      flow.field_indicator          |= FLW_TCP_MASK;
   } else if ((pkt.field_indicator & PCKT_UDP_MASK) == PCKT_UDP_MASK) {
      flow.src_port                  = pkt.src_port;
      flow.dst_port                  = pkt.dst_port;
      flow.field_indicator          |= FLW_UDP_MASK;
   } else if (pkt.field_indicator & PCKT_ICMP) {
      flow.src_port                  = pkt.src_port;
      flow.dst_port                  = pkt.dst_port;
      flow.field_indicator          |= FLW_ICMP;
   }

   empty_flow = false;
}

void FlowRecord::update(const Packet &pkt)
{
   flow.pkt_total_cnt += 1;
   if ((pkt.field_indicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK) {
      flow.time_last = pkt.timestamp;
   }
   if ((pkt.field_indicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      flow.octet_total_length += pkt.ip_length;
   }
   if ((pkt.field_indicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      flow.octet_total_length += pkt.ip_length;
   }
   if ((pkt.field_indicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) {
      flow.tcp_control_bits |= pkt.tcp_control_bits;
   }
}

// NHTFlowCache -- PUBLIC *****************************************************

void NHTFlowCache::init()
{
   plugins_init();
}

void NHTFlowCache::finish()
{
   plugins_finish();
   export_expired(true); // export whole cache

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

   uint32_t hashval = SuperFastHash(key, key_len); /* Calculates hash value from key created before. */

   uint32_t line_index = (hashval % size) & line_size_mask; /* Find place for packet. */
   uint32_t flow_index = 0, next_line = line_index + line_size;
   bool found = false;
   FlowRecord *flow; /* Pointer to flow we will be working with. */

   /* Find existing flow record in flow cache. */
   for (flow_index = line_index; flow_index < next_line; flow_index++) {
      if (flow_array[flow_index]->belongs(hashval, key, key_len)) {
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
      int flow_index_start = line_index;

      flow = flow_array[flow_index];
      for (int j = flow_index; j > flow_index_start; j--) {
         flow_array[j] = flow_array[j - 1];
      }

      flow_array[flow_index_start] = flow;
      flow_index = flow_index_start;
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
         int flow_index_start = line_index + 13;
         flow = flow_array[flow_index];
         flow->erase();
         for (int j = flow_index; j > flow_index_start; j--) {
            flow_array[j] = flow_array[j - 1];
         }
         flow_index = flow_index_start;
         flow_array[flow_index] = flow;
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
      flow->create(pkt, hashval, key, key_len);
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
      export_expired(false); // false -- export only expired flows
      last_ts = current_ts;
   }

   return 0;
}

int NHTFlowCache::export_expired(bool export_all)
{
   int exported = 0;
   for (unsigned int i = 0; i < size; i++) {
      if (is_expired(flow_array[i], current_ts, active, inactive) ||
         (export_all && !flow_array[i]->is_empty())) {
         plugins_pre_export(flow_array[i]->flow);
         exporter->export_flow(flow_array[i]->flow);

         flow_array[i]->erase();
#ifdef FLOW_CACHE_STATS
         expired++;
#endif /* FLOW_CACHE_STATS */
         exported++;
      }
   }
   return exported;
}

// NHTFlowCache -- PROTECTED **************************************************

bool NHTFlowCache::create_hash_key(Packet &pkt)
{
   char *k = key;

   if ((pkt.field_indicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      *(uint8_t *) k = pkt.ip_proto;
      k += sizeof(pkt.ip_proto);
      *(uint32_t *) k = pkt.src_ip.v4;
      k += sizeof(pkt.src_ip.v4);
      *(uint32_t *) k = pkt.dst_ip.v4;
      k += sizeof(pkt.dst_ip.v4);
      *(uint16_t *) k = pkt.src_port;
      k += sizeof(pkt.src_port);
      *(uint16_t *) k = pkt.dst_port;
      k += sizeof(pkt.dst_port);
      key_len = 13;
   } else if ((pkt.field_indicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      *(uint8_t *) k = pkt.ip_proto;
      k += sizeof(pkt.ip_proto);
      memcpy(k, pkt.src_ip.v6, sizeof(pkt.src_ip.v6));
      k += sizeof(pkt.src_ip.v6);
      memcpy(k, pkt.dst_ip.v6, sizeof(pkt.src_ip.v6));
      k += sizeof(pkt.dst_ip.v6);
      *(uint16_t *) k = pkt.src_port;
      k += sizeof(pkt.src_port);
      *(uint16_t *) k = pkt.dst_port;
      k += sizeof(pkt.dst_port);
      key_len = 37;
   } else {
      return false;
   }

   return true;
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
