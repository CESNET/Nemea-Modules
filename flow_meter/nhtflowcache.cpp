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
#include <nemea-common/super_fast_hash.h>

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
inline bool is_expired(const Flow *flow, const struct timeval &current_ts,
                       const struct timeval &active, const struct timeval &inactive)
{
   if (!flow->is_empty() && ( current_ts.tv_sec - flow->flow_record.start_timestamp.tv_sec >= active.tv_sec ||
      current_ts.tv_sec - flow->flow_record.end_timestamp.tv_sec >= inactive.tv_sec)) {
      return true;
   } else {
      return false;
   }
}

inline bool Flow::is_empty() const
{
   return empty_flow;
}

bool Flow::belongs(uint64_t pkt_hash, char *pkt_key, uint8_t key_len) const
{
   if (is_empty() || (pkt_hash != hash)) {
      return false;
   } else {
      return (memcmp(key, pkt_key, key_len) == 0);
   }
}

void Flow::create(const Packet &pkt, uint64_t pkt_hash, char *pkt_key, uint8_t key_len)
{
   flow_record.field_indicator    = FLW_FLOWFIELDINDICATOR;
   flow_record.pkt_total_cnt      = 1;
   flow_record.field_indicator   |= FLW_PACKETTOTALCOUNT;

   hash = pkt_hash;
   memcpy(key, pkt_key, key_len);

   if ((pkt.field_indicator & PCKT_INFO_MASK) == PCKT_INFO_MASK) {
      flow_record.field_indicator |= FLW_HASH;
   }

   if ((pkt.field_indicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK) {
      flow_record.start_timestamp          = pkt.timestamp;
      flow_record.end_timestamp            = pkt.timestamp;
      flow_record.field_indicator         |= FLW_TIMESTAMPS_MASK;
   }

   if ((pkt.field_indicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      flow_record.ip_version               = pkt.ip_version;
      flow_record.ip_proto                 = pkt.ip_proto;
      flow_record.ip_tos                   = pkt.ip_tos;
      flow_record.ip_ttl                   = pkt.ip_ttl;
      flow_record.src_ip.v4                = pkt.src_ip.v4;
      flow_record.dst_ip.v4                = pkt.dst_ip.v4;
      flow_record.octet_total_length       = pkt.ip_length;
      flow_record.field_indicator         |= (FLW_IPV4_MASK | FLW_IPSTAT_MASK);
   } else if ((pkt.field_indicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      flow_record.ip_version               = pkt.ip_version;
      flow_record.ip_proto                 = pkt.ip_proto;
      flow_record.ip_tos                   = pkt.ip_tos;
      memcpy(flow_record.src_ip.v6, pkt.src_ip.v6, 16);
      memcpy(flow_record.dst_ip.v6, pkt.dst_ip.v6, 16);
      flow_record.octet_total_length         = pkt.ip_length;
      flow_record.field_indicator           |= (FLW_IPV6_MASK | FLW_IPSTAT_MASK);
   }

   if ((pkt.field_indicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) {
      flow_record.src_port                  = pkt.src_port;
      flow_record.dst_port                  = pkt.dst_port;
      flow_record.tcp_control_bits          = pkt.tcp_control_bits;
      flow_record.field_indicator          |= FLW_TCP_MASK;
   } else if ((pkt.field_indicator & PCKT_UDP_MASK) == PCKT_UDP_MASK) {
      flow_record.src_port                  = pkt.src_port;
      flow_record.dst_port                  = pkt.dst_port;
      flow_record.field_indicator          |= FLW_UDP_MASK;
   }

   empty_flow = false;
}

void Flow::update(const Packet &pkt)
{
   flow_record.pkt_total_cnt += 1;
   if ((pkt.field_indicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK) {
      flow_record.end_timestamp = pkt.timestamp;
   }
   if ((pkt.field_indicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      flow_record.octet_total_length += pkt.ip_length;
   }
   if ((pkt.field_indicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      flow_record.octet_total_length += pkt.ip_length;
   }
   if ((pkt.field_indicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) {
      flow_record.tcp_control_bits |= pkt.tcp_control_bits;
   }
}

// NHTFlowCache -- PUBLIC *****************************************************

void NHTFlowCache::init()
{
   plugins_init();
   parse_replacement_string();
   insertpos = rpl[0];
   rpl.assign(rpl.begin() + 1, rpl.end());
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

   uint32_t hashval = SuperFastHash(key, key_len); // calculates hash value from key created before

   // Find place for packet
   int line_index = ((hashval % size) / line_size) * line_size;

   bool found = false;
   int flow_index = 0;

   for (flow_index = line_index; flow_index < (line_index + line_size); flow_index++) {
      if (flow_array[flow_index]->belongs(hashval, key, key_len)) {
         found = true;
         break;
      }
   }

   if (found) {
#ifdef FLOWCACHE_STATS
      lookups += (flow_index - line_index + 1);
      lookups2 += (flow_index - line_index + 1) * (flow_index - line_index + 1);
#endif /* FLOWCACHE_STATS */
      int relpos = flow_index - line_index;
      int newrel = rpl[relpos];
      int flow_index_start = line_index + newrel;

      Flow *ptr_flow = flow_array[flow_index];
      for (int j = flow_index; j > flow_index_start; j--) {
         flow_array[j] = flow_array[j - 1];
      }

      flow_array[flow_index_start] = ptr_flow;
      flow_index = flow_index_start;
#ifdef FLOWCACHE_STATS
      hits++;
#endif /* FLOWCACHE_STATS */
   } else {
      for (flow_index = line_index; flow_index < (line_index + line_size); flow_index++) {
         if (flow_array[flow_index]->is_empty()) {
            found = true;
            break;
         }
      }
      if (!found) {
         flow_index = line_index + line_size - 1;

         // Export flow
         plugins_pre_export(flow_array[flow_index]->flow_record);
         exporter->export_flow(flow_array[flow_index]->flow_record);

#ifdef FLOWCACHE_STATS
         expired++;
#endif /* FLOWCACHE_STATS */
         int flow_index_start = line_index + insertpos;
         Flow *ptr_flow = flow_array[flow_index];
         ptr_flow->erase();
         for (int j = flow_index; j > flow_index_start; j--) {
            flow_array[j] = flow_array[j - 1];
         }
         flow_index = flow_index_start;
         flow_array[flow_index] = ptr_flow;
#ifdef FLOWCACHE_STATS
         not_empty++;
      else {
         empty++;
#endif /* FLOWCACHE_STATS */
      }
   }

   current_ts = pkt.timestamp;
   if (flow_array[flow_index]->is_empty()) {
      flow_array[flow_index]->create(pkt, hashval, key, key_len);
      ret = plugins_post_create(flow_array[flow_index]->flow_record, pkt);

      if (ret & FLOW_FLUSH) {
         exporter->export_flow(flow_array[flow_index]->flow_record);
#ifdef FLOWCACHE_STATS
         flushed++;
#endif /* FLOWCACHE_STATS */
         flow_array[flow_index]->erase();
      }
   } else {
      ret = plugins_pre_update(flow_array[flow_index]->flow_record, pkt);

      if (ret & FLOW_FLUSH) {
         exporter->export_flow(flow_array[flow_index]->flow_record);
#ifdef FLOWCACHE_STATS
         flushed++;
#endif /* FLOWCACHE_STATS */
         flow_array[flow_index]->erase();

         return put_pkt(pkt);
      } else {
         flow_array[flow_index]->update(pkt);
         ret = plugins_post_update(flow_array[flow_index]->flow_record, pkt);

         if (ret & FLOW_FLUSH) {
            exporter->export_flow(flow_array[flow_index]->flow_record);
#ifdef FLOWCACHE_STATS
            flushed++;
#endif /* FLOWCACHE_STATS */
            flow_array[flow_index]->erase();

            return put_pkt(pkt);
         }
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
   for (int i = 0; i < size; i++) {
      if (is_expired(flow_array[i], current_ts, active, inactive) ||
         (export_all && !flow_array[i]->is_empty())) {
         plugins_pre_export(flow_array[i]->flow_record);
         exporter->export_flow(flow_array[i]->flow_record);

         flow_array[i]->erase();
#ifdef FLOWCACHE_STATS
         expired++;
#endif /* FLOWCACHE_STATS */
         exported++;
      }
   }
   return exported;
}

// NHTFlowCache -- PROTECTED **************************************************

void NHTFlowCache::parse_replacement_string()
{
   size_t search_pos = 0;
   size_t search_pos_old = 0;

   while ((search_pos = policy.find(',', search_pos)) != string::npos) {
      rpl.push_back(atoi((char *) policy.substr(search_pos_old, search_pos - search_pos_old).c_str()));
      search_pos++;
      search_pos_old = search_pos;
   }
   rpl.push_back(atoi((char *) policy.substr(search_pos_old).c_str()));
}

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
      *k = '\0';
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
      *k = '\0';
      key_len = 37;
   } else {
      return false;
   }

   return true;
}

void NHTFlowCache::print_report()
{
#ifdef FLOWCACHE_STATS
   float tmp = float(lookups) / hits;

   cout << "Hits: " << hits << endl;
   cout << "Empty: " << empty << endl;
   cout << "Not empty: " << not_empty << endl;
   cout << "Expired: " << expired << endl;
   cout << "Flushed: " << flushed << endl;
   cout << "Average Lookup:  " << tmp << endl;
   cout << "Variance Lookup: " << float(lookups2) / hits - tmp * tmp << endl;
#endif /* FLOWCACHE_STATS */
}
