/**
 * \file nhtflowcache.h
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
#ifndef NHTFLOWCACHE_H
#define NHTFLOWCACHE_H

#include "flow_meter.h"
#include "flowcache.h"
#include "flowifc.h"
#include "flowexporter.h"
#include <string>

#define MAX_KEYLENGTH 76

class Flow
{
   uint64_t hash;
   struct timeval inactive;
   struct timeval active;
   char key[MAX_KEYLENGTH];

public:
   bool empty_flow;
   FlowRecord flowrecord;

   void erase()
   {
      flowrecord.removeExtensions();
      memset(&flowrecord, 0, sizeof(flowrecord));
      empty_flow = true;
   }

   Flow(const struct timeval &inactivetimeout, const struct timeval &activetimeout)
   {
      erase();
      this->inactive = inactivetimeout;
      this->active = activetimeout;
   };
   ~Flow()
   {
   };

   bool isempty();
   inline bool isexpired(const struct timeval &current_ts);
   bool belongs(uint64_t pkt_hash, char *pkt_key, uint8_t key_len);
   void create(Packet pkt, uint64_t pkt_hash, char *pkt_key, uint8_t key_len);
   void update(Packet pkt);
};

typedef std::vector<int> replacementvector_t;
typedef replacementvector_t::iterator replacementvectoriter_t;

typedef std::vector<Flow *> ptrflowvector_t;
typedef ptrflowvector_t::iterator ptrflowvectoriter_t;

class NHTFlowCache : public FlowCache
{
   bool statsout;
   uint8_t key_len;
   int linesize;
   int size;
   int insertpos;
   long empty;
   long notempty;
   long hits;
   long expired;
   long flushed;
   long lookups;
   long lookups2;
   struct timeval currtimestamp;
   struct timeval lasttimestamp;
   char key[MAX_KEYLENGTH];
   std::string policy;
   replacementvector_t rpl;
   ptrflowvector_t flowexportqueue;
   Flow **flowarray;

public:
   NHTFlowCache(const options_t &options)
   {
      this->linesize = options.flowlinesize;
      this->empty = 0;
      this->notempty = 0;
      this->hits = 0;
      this->expired = 0;
      this->flushed = 0;
      this->size = options.flowcachesize;
      this->lookups = 0;
      this->lookups2 = 0;
      this->policy = options.replacementstring;
      this->statsout = options.statsout;

      flowarray = new Flow*[size];
      for (int i = 0; i < size; i++) {
         flowarray[i] = new Flow(options.inactivetimeout, options.activetimeout);
      }
   };
   ~NHTFlowCache()
   {
      for (int i = 0; i < size; i++) {
         delete flowarray[i];
      }
      delete [] flowarray;

      while (!flowexportqueue.empty()) {
         delete flowexportqueue.back();
         flowexportqueue.pop_back();
      }
   };

// Put packet into the cache (i.e. update corresponding flow record or create a new one)
   virtual int put_pkt(Packet &pkt);
   virtual void init();
   virtual void finish();

   int exportexpired(bool exportall);

protected:
   void parsereplacementstring();
   void createhashkey(Packet pkt);
   long calculatehash();
   int flushflows();
   void endreport();
};

#endif
