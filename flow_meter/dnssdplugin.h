/**
 * \file dnssdplugin.h
 * \brief Plugin for parsing dnssd traffic.
 * \author Ondrej Sedlacek xsedla1o@stud.fit.vutbr.cz
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

#ifndef DNSSDPLUGIN_H
#define DNSSDPLUGIN_H

#include <string>
#include <sstream>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "dns.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed DNSSD packets.
 */
struct RecordExtDNSSD : RecordExt {
   string ph;
   uint16_t id;
   uint16_t answers;
   uint8_t rcode;
   char qname[128];
   uint16_t qtype;
   uint16_t qclass;
   uint32_t rr_ttl;
   uint16_t rlength;
   char data[160];
   uint16_t psize;
   uint8_t dns_do;

   /**
    * \brief Constructor.
    */
   RecordExtDNSSD() : RecordExt(dnssd)
   {
      ph = "";
      id = 0;
      answers = 0;
      rcode = 0;
      qname[0] = 0;
      qtype = 0;
      qclass = 0;
      rr_ttl = 0;
      rlength = 0;
      data[0] = 0;
      psize = 0;
      dns_do = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_set_string(tmplt, record, F_DNSSD_PLACEHOLDER, ph.c_str());
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length = 0;
      int ph_len = ph.length();

      if (ph_len + 1 > size) {
         return -1;
      }

      buffer[length++] = ph_len;
      memcpy(buffer + length, ph.c_str(), ph_len);
      length += ph_len;

      return length;
   }
};

/**
 * \brief Flow cache plugin for parsing DNSSD packets.
 */
class DNSSDPlugin : public FlowCachePlugin
{
public:
   DNSSDPlugin(const options_t &module_options);
   DNSSDPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();

private:
   bool parse_dns(const char *data, unsigned int payload_len, bool tcp, RecordExtDNSSD *rec);
   int  add_ext_dnssd(const char *data, unsigned int payload_len, bool tcp, Flow &rec);
   void process_srv(string &str) const;
   void process_rdata(const char *record_begin, const char *data, ostringstream &rdata, uint16_t type, size_t length) const;
   void filtered_append(RecordExtDNSSD *rec, string name, string head, int type);

   string get_name(const char *data) const;
   size_t get_name_length(const char *data) const;

   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t queries;       /**< Total number of parsed DNS queries. */
   uint32_t responses;     /**< Total number of parsed DNS responses. */
   uint32_t total;         /**< Total number of parsed DNS packets. */

   const char *data_begin; /**< Pointer to begin of payload. */
   uint32_t data_len;      /**< Length of packet payload. */
};

#endif
