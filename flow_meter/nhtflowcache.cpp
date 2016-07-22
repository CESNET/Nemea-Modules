/**
 * \file nhtflowcache.cpp
 * \brief "NewHashTable" flow cache
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2014-2015 CESNET
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
#include "nhtflowcache.h"
#include "flowcache.h"

#include <cstdlib>
#include <iostream>
#include <locale>
#include <sys/time.h>

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
   struct timeval tmp1, tmp2;
   timersub(&current_ts, &flow->flowrecord.flowStartTimestamp, &tmp1);
   timersub(&current_ts, &flow->flowrecord.flowEndTimestamp, &tmp2);

   if (!flow->isempty() && (timercmp(&tmp1, &active, >) || timercmp(&tmp2, &inactive, >))) {
      return true;
   } else {
      return false;
   }
}

bool Flow::isempty() const
{
   return empty_flow;
}

bool Flow::belongs(uint64_t pkt_hash, char *pkt_key, uint8_t key_len) const
{
   if (isempty() || (pkt_hash != hash)) {
      return false;
   } else {
      return (memcmp(key, pkt_key, key_len) == 0);
   }
}

void Flow::create(Packet pkt, uint64_t pkt_hash, char *pkt_key, uint8_t key_len)
{
   flowrecord.flowFieldIndicator    = FLW_FLOWFIELDINDICATOR;
   flowrecord.packetTotalCount      = 1;
   flowrecord.flowFieldIndicator    |= FLW_PACKETTOTALCOUNT;

   hash = pkt_hash;
   memcpy(key, pkt_key, key_len);

   if ((pkt.packetFieldIndicator & PCKT_INFO_MASK) == PCKT_INFO_MASK) {
      flowrecord.flowFieldIndicator |= FLW_HASH;
   }

   if ((pkt.packetFieldIndicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK) {
      flowrecord.flowStartTimestamp    = pkt.timestamp;
      flowrecord.flowEndTimestamp      = pkt.timestamp;
      flowrecord.flowFieldIndicator    |= FLW_TIMESTAMPS_MASK;
   }

   if ((pkt.packetFieldIndicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      flowrecord.ipVersion                = pkt.ipVersion;
      flowrecord.protocolIdentifier       = pkt.protocolIdentifier;
      flowrecord.ipClassOfService         = pkt.ipClassOfService;
      flowrecord.ipTtl                    = pkt.ipTtl;
      flowrecord.sourceIPAddress.v4       = pkt.sourceIPAddress.v4;
      flowrecord.destinationIPAddress.v4  = pkt.destinationIPAddress.v4;
      flowrecord.octetTotalLength         = pkt.ipLength;
      flowrecord.flowFieldIndicator      |= (FLW_IPV4_MASK | FLW_IPSTAT_MASK);
   } else if ((pkt.packetFieldIndicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      flowrecord.ipVersion                = pkt.ipVersion;
      flowrecord.protocolIdentifier       = pkt.protocolIdentifier;
      flowrecord.ipClassOfService         = pkt.ipClassOfService;
      memcpy(flowrecord.sourceIPAddress.v6, pkt.sourceIPAddress.v6, 16);
      memcpy(flowrecord.destinationIPAddress.v6, pkt.destinationIPAddress.v6, 16);
      flowrecord.octetTotalLength         = pkt.ipLength;
      flowrecord.flowFieldIndicator      |= (FLW_IPV6_MASK | FLW_IPSTAT_MASK);
   }

   if ((pkt.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) {
      flowrecord.sourceTransportPort      = pkt.sourceTransportPort;
      flowrecord.destinationTransportPort = pkt.destinationTransportPort;
      flowrecord.tcpControlBits           = pkt.tcpControlBits;
      flowrecord.flowFieldIndicator       |= FLW_TCP_MASK;
   } else if ((pkt.packetFieldIndicator & PCKT_UDP_MASK) == PCKT_UDP_MASK) {
      flowrecord.sourceTransportPort      = pkt.sourceTransportPort;
      flowrecord.destinationTransportPort = pkt.destinationTransportPort;
      flowrecord.flowFieldIndicator       |= FLW_UDP_MASK;
   }

   empty_flow = false;
}

void Flow::update(Packet pkt)
{
   flowrecord.packetTotalCount += 1;
   if ((pkt.packetFieldIndicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK) {
      flowrecord.flowEndTimestamp = pkt.timestamp;
   }
   if ((pkt.packetFieldIndicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      flowrecord.octetTotalLength += pkt.ipLength;
   }
   if ((pkt.packetFieldIndicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      flowrecord.octetTotalLength += pkt.ipLength;
   }
   if ((pkt.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) {
      flowrecord.tcpControlBits |= pkt.tcpControlBits;
   }
}

// NHTFlowCache -- PUBLIC *****************************************************

void NHTFlowCache::init()
{
   plugins_init();
   parsereplacementstring();
   insertpos = rpl[0];
   rpl.assign(rpl.begin() + 1, rpl.end());
}

void NHTFlowCache::finish()
{
   plugins_finish();
   exportexpired(true); // export whole cache

   if (!statsout) {
      endreport();
   }
}

int NHTFlowCache::put_pkt(Packet &pkt)
{
   createhashkey(pkt); // saves key value and key length into attributes NHTFlowCache::key and NHTFlowCache::key_len
   uint64_t hashval = calculatehash(); // calculates hash value from key created before

   // Find place for packet
   int lineindex = ((hashval % size) / linesize) * linesize;

   bool found = false;
   int flowindex = 0;

   for (flowindex = lineindex; flowindex < (lineindex + linesize); flowindex++) {
      if (flowarray[flowindex]->belongs(hashval, key, key_len)) {
         found = true;
         break;
      }
   }

   if (found) {
      lookups += (flowindex - lineindex + 1);
      lookups2 += (flowindex - lineindex + 1) * (flowindex - lineindex + 1);
      int relpos = flowindex - lineindex;
      int newrel = rpl[relpos];
      int flowindexstart = lineindex + newrel;

      Flow *ptrflow = flowarray[flowindex];
      for (int j = flowindex; j > flowindexstart; j--) {
         flowarray[j] = flowarray[j - 1];
      }

      flowarray[flowindexstart] = ptrflow;
      flowindex = flowindexstart;
      hits++;
   } else {
      for (flowindex = lineindex; flowindex < (lineindex + linesize); flowindex++) {
         if (flowarray[flowindex]->isempty()) {
            found = true;
            break;
         }
      }
      if (!found) {
         flowindex = lineindex + linesize - 1;

         // Export flow
         plugins_pre_export(flowarray[flowindex]->flowrecord);
         exporter->export_flow(flowarray[flowindex]->flowrecord);

         expired++;
         int flowindexstart = lineindex + insertpos;
         Flow *ptrflow = flowarray[flowindex];
         ptrflow->erase();
         for (int j = flowindex; j > flowindexstart; j--) {
            flowarray[j] = flowarray[j - 1];
         }
         flowindex = flowindexstart;
         flowarray[flowindex] = ptrflow;
         notempty++;
      } else {
         empty++;
      }
   }

   int ret = 0;
   currtimestamp = pkt.timestamp;
   if (flowarray[flowindex]->isempty()) {
      flowarray[flowindex]->create(pkt, hashval, key, key_len);
      ret = plugins_post_create(flowarray[flowindex]->flowrecord, pkt);

      if (ret & FLOW_FLUSH) {
         exporter->export_flow(flowarray[flowindex]->flowrecord);
         flushed++;
         flowarray[flowindex]->erase();
      }
   } else {
      ret = plugins_pre_update(flowarray[flowindex]->flowrecord, pkt);

      if (ret & FLOW_FLUSH) {
         exporter->export_flow(flowarray[flowindex]->flowrecord);
         flushed++;
         flowarray[flowindex]->erase();

         return put_pkt(pkt);
      } else {
         flowarray[flowindex]->update(pkt);
         ret = plugins_post_update(flowarray[flowindex]->flowrecord, pkt);

         if (ret & FLOW_FLUSH) {
            exporter->export_flow(flowarray[flowindex]->flowrecord);
            flushed++;
            flowarray[flowindex]->erase();

            return put_pkt(pkt);
         }
      }
   }

   if (currtimestamp.tv_sec - lasttimestamp.tv_sec > 5) {
      exportexpired(false); // false -- export only expired flows
      lasttimestamp = currtimestamp;
   }

   return 0;
}

// NHTFlowCache -- PROTECTED **************************************************

void NHTFlowCache::parsereplacementstring()
{
   size_t searchpos = 0;
   size_t searchposold = 0;

   while ((searchpos = policy.find(',', searchpos)) != string::npos) {
      rpl.push_back(atoi((char *) policy.substr(searchposold, searchpos-searchposold).c_str()));
      searchpos++;
      searchposold = searchpos;
   }
   rpl.push_back(atoi((char *) policy.substr(searchposold).c_str()));
}

long NHTFlowCache::calculatehash()
{
   locale loc;
   const collate<char> &coll = use_facet<collate<char> >(loc);
   return coll.hash(key, key + key_len);
}

void NHTFlowCache::createhashkey(Packet pkt)
{
   char *k = key;

   if ((pkt.packetFieldIndicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      *(uint8_t *) k = pkt.protocolIdentifier;
      k += sizeof(pkt.protocolIdentifier);
      *(uint32_t *) k = pkt.sourceIPAddress.v4;
      k += sizeof(pkt.sourceIPAddress.v4);
      *(uint32_t *) k = pkt.destinationIPAddress.v4;
      k += sizeof(pkt.destinationIPAddress.v4);
      *(uint16_t *) k = pkt.sourceTransportPort;
      k += sizeof(pkt.sourceTransportPort);
      *(uint16_t *) k = pkt.destinationTransportPort;
      k += sizeof(pkt.destinationTransportPort);
      *k = '\0';
      key_len = 13;
   }

   if ((pkt.packetFieldIndicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      *(uint8_t *) k = pkt.protocolIdentifier;
      k += sizeof(pkt.protocolIdentifier);
      memcpy(k, pkt.sourceIPAddress.v6, sizeof(pkt.sourceIPAddress.v6));
      k += sizeof(pkt.sourceIPAddress.v6);
      memcpy(k, pkt.destinationIPAddress.v6, sizeof(pkt.sourceIPAddress.v6));
      k += sizeof(pkt.destinationIPAddress.v6);
      *(uint16_t *) k = pkt.sourceTransportPort;
      k += sizeof(pkt.sourceTransportPort);
      *(uint16_t *) k = pkt.destinationTransportPort;
      k += sizeof(pkt.destinationTransportPort);
      *k = '\0';
      key_len = 37;
   }
}

int NHTFlowCache::exportexpired(bool exportall)
{
   int exported = 0;
   bool result = false;
   for (int i = 0; i < size; i++) {
      if (exportall && !flowarray[i]->isempty()) {
         result = true;
      }
      if (!exportall && is_expired(flowarray[i], currtimestamp, active, inactive)) {
         result = true;
      }
      if (result) {
         plugins_pre_export(flowarray[i]->flowrecord);
         exporter->export_flow(flowarray[i]->flowrecord);

         flowarray[i]->erase();
         expired++;
         exported++;
         result = false;
      }
   }
   return exported;
}

void NHTFlowCache::endreport()
{
   float a = float(lookups) / hits;

   cout << "Hits: " << hits << endl;
   cout << "Empty: " << empty << endl;
   cout << "Not empty: " << notempty << endl;
   cout << "Expired: " << expired << endl;
   cout << "Flushed: " << flushed << endl;
   cout << "Average Lookup:  " << a << endl;
   cout << "Variance Lookup: " << float(lookups2) / hits - a * a << endl;
}
