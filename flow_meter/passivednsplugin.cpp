/**
 * \file passivednsplugin.cpp
 * \brief Plugin for exporting DNS A and AAAA records.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <unirec/unirec.h>
#include <limits>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "passivednsplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"
#include "conversion.h"

using namespace std;

//#define DEBUG_PASSIVEDNS

// Print debug message if debugging is allowed.
#ifdef DEBUG_PASSIVEDNS
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_PASSIVEDNS
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

/**
 * \brief Check for label pointer in DNS name.
 */
#define IS_POINTER(ch) ((ch & 0xC0) == 0xC0)

#define MAX_LABEL_CNT 127

/**
 * \brief Get offset from 2 byte pointer.
 */
#define GET_OFFSET(half1, half2) ((((uint8_t)(half1) & 0x3F) << 8) | (uint8_t)(half2))

#define DNS_UNIREC_TEMPLATE "DNS_ID,DNS_ATYPE,DNS_NAME,DNS_RR_TTL,DNS_IP"

UR_FIELDS (
   uint16 DNS_ID,
   uint16 DNS_ATYPE,
   string DNS_NAME,
   uint32 DNS_RR_TTL,
   ipaddr DNS_IP
)

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
PassiveDNSPlugin::PassiveDNSPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
   total = 0;
   parsed_a = 0;
   parsed_aaaa = 0;
   parsed_ptr = 0;
}

PassiveDNSPlugin::PassiveDNSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   total = 0;
   parsed_a = 0;
   parsed_aaaa = 0;
   parsed_ptr = 0;
}

int PassiveDNSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.src_port == 53) {
      return add_ext_dns(pkt.payload, pkt.payload_length, pkt.ip_proto == IPPROTO_TCP, rec);
   }

   return 0;
}

int PassiveDNSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   if (pkt.src_port == 53) {
      return add_ext_dns(pkt.payload, pkt.payload_length, pkt.ip_proto == IPPROTO_TCP, rec);
   }

   return 0;
}

void PassiveDNSPlugin::finish()
{
   if (print_stats) {
      cout << "PassiveDNS plugin stats:" << endl;
      cout << "   Parsed dns responses: " << total << endl;
      cout << "   Parsed A records: " << parsed_a << endl;
      cout << "   Parsed AAAA records: " << parsed_aaaa << endl;
      cout << "   Parsed PTR records: " << parsed_ptr << endl;
   }
}

string PassiveDNSPlugin::get_unirec_field_string()
{
   return DNS_UNIREC_TEMPLATE;
}

const char *passivedns_ipfix_string[] = {
   IPFIX_PASSIVEDNS_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **PassiveDNSPlugin::get_ipfix_string()
{
   return passivedns_ipfix_string;
}

/**
 * \brief Get name length.
 * \param [in] data Pointer to string.
 * \return Number of characters in string.
 */
size_t PassiveDNSPlugin::get_name_length(const char *data) const
{
   size_t len = 0;

   while (1) {
      if ((uint32_t) (data - data_begin) + 1 > data_len) {
         throw "Error: overflow";
      }
      if (!data[0]) {
         break;
      }
      if (IS_POINTER(data[0])) {
         return len + 2;
      }

      len += (uint8_t) data[0] + 1;
      data += (uint8_t) data[0] + 1;
   }

   return len + 1;
}

/**
 * \brief Decompress dns name.
 * \param [in] data Pointer to compressed data.
 * \return String with decompressed dns name.
 */
string PassiveDNSPlugin::get_name(const char *data) const
{
   string name = "";
   int label_cnt = 0;

   if ((uint32_t) (data - data_begin) > data_len) {
      throw "Error: overflow";
   }

   while (data[0]) { /* Check for terminating character. */
      if (IS_POINTER(data[0])) { /* Check for label pointer (11xxxxxx byte) */
         data = data_begin + GET_OFFSET(data[0], data[1]);

         /* Check for possible errors.*/
         if (label_cnt++ > MAX_LABEL_CNT || (uint32_t) (data - data_begin) > data_len) {
            throw "Error: label count exceed or overflow";
         }

         continue;
      }

      /* Check for possible errors.*/
      if (label_cnt++ > MAX_LABEL_CNT || (uint8_t) data[0] > 63 ||
         (uint32_t) ((data - data_begin) + (uint8_t) data[0] + 2) > data_len) {
         throw "Error: label count exceed or overflow";
      }

      name += '.' + string(data + 1, (uint8_t) data[0]);
      data += ((uint8_t) data[0] + 1);
   }

   if (name[0] == '.') {
      name.erase(0, 1);
   }

   return name;
}

/**
 * \brief Parse and store DNS packet.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \return True if DNS was parsed.
 */
RecordExtPassiveDNS *PassiveDNSPlugin::parse_dns(const char *data, unsigned int payload_len, bool tcp)
{
   RecordExtPassiveDNS *list = NULL;

   try {
      total++;

      DEBUG_MSG("---------- dns parser #%u ----------\n", total);
      DEBUG_MSG("Payload length: %u\n", payload_len);

      if (tcp) {
         payload_len -= 2;
         if (ntohs(*(uint16_t *) data) != payload_len) {
            DEBUG_MSG("parser quits: fragmented tcp pkt");
            return NULL;
         }
         data += 2;
      }

      if (payload_len < sizeof(struct dns_hdr)) {
         DEBUG_MSG("parser quits: payload length < %ld\n", sizeof(struct dns_hdr));
         return NULL;
      }

      data_begin = data;
      data_len = payload_len;

      struct dns_hdr *dns = (struct dns_hdr *) data;
      //uint16_t flags = ntohs(dns->flags);
      uint16_t question_cnt = ntohs(dns->question_rec_cnt);
      uint16_t answer_rr_cnt = ntohs(dns->answer_rec_cnt);

      DEBUG_MSG("DNS message header\n");
      DEBUG_MSG("\tTransaction ID:\t\t%#06x\n",       ntohs(dns->id));
      DEBUG_MSG("\tFlags:\t\t\t%#06x\n",              ntohs(dns->flags));

      DEBUG_MSG("\t\tQuestion/reply:\t\t%u\n",        DNS_HDR_GET_QR(flags));
      DEBUG_MSG("\t\tOP code:\t\t%u\n",               DNS_HDR_GET_OPCODE(flags));
      DEBUG_MSG("\t\tAuthoritative answer:\t%u\n",    DNS_HDR_GET_AA(flags));
      DEBUG_MSG("\t\tTruncation:\t\t%u\n",            DNS_HDR_GET_TC(flags));
      DEBUG_MSG("\t\tRecursion desired:\t%u\n",       DNS_HDR_GET_RD(flags));
      DEBUG_MSG("\t\tRecursion available:\t%u\n",     DNS_HDR_GET_RA(flags));
      DEBUG_MSG("\t\tReserved:\t\t%u\n",              DNS_HDR_GET_Z(flags));
      DEBUG_MSG("\t\tAuth data:\t\t%u\n",             DNS_HDR_GET_AD(flags));
      DEBUG_MSG("\t\tChecking disabled:\t%u\n",       DNS_HDR_GET_CD(flags));
      DEBUG_MSG("\t\tResponse code:\t\t%u\n",         DNS_HDR_GET_RESPCODE(flags));

      DEBUG_MSG("\tQuestions:\t\t%u\n",               question_cnt);
      DEBUG_MSG("\tAnswer RRs:\t\t%u\n",              answer_rr_cnt);
      DEBUG_MSG("\tAuthority RRs:\t\t%u\n",           authority_rr_cnt);
      DEBUG_MSG("\tAdditional RRs:\t\t%u\n",          additional_rr_cnt);

      /********************************************************************
      *****                   DNS Question section                    *****
      ********************************************************************/
      data += sizeof(struct dns_hdr);
      for (int i = 0; i < question_cnt; i++) {
         DEBUG_MSG("\nDNS question #%d\n",            i + 1);
         DEBUG_MSG("\tName:\t\t\t%s\n",               name.c_str());

         data += get_name_length(data);

         if ((data - data_begin) + sizeof(struct dns_question) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return NULL;
         }

         DEBUG_MSG("\tType:\t\t\t%u\n",               ntohs(question->qtype));
         DEBUG_MSG("\tClass:\t\t\t%u\n",              ntohs(question->qclass));
         data += sizeof(struct dns_question);
      }

      /********************************************************************
      *****                    DNS Answers section                    *****
      ********************************************************************/
      size_t rdlength;
      for (int i = 0; i < answer_rr_cnt; i++) { // Process answers section.
         DEBUG_MSG("DNS answer #%d\n", i + 1);
         DEBUG_MSG("\tAnswer name:\t\t%s\n",          get_name(data).c_str());
         string name = get_name(data);
         data += get_name_length(data);

         struct dns_answer *answer = (struct dns_answer *) data;

         uint32_t tmp = (data - data_begin) + sizeof(dns_answer);
         if (tmp > payload_len || tmp + ntohs(answer->rdlength) > payload_len) {
            DEBUG_MSG("DNS parser quits: overflow\n\n");
            return list;
         }

         DEBUG_MSG("\tType:\t\t\t%u\n",               ntohs(answer->atype));
         DEBUG_MSG("\tClass:\t\t\t%u\n",              ntohs(answer->aclass));
         DEBUG_MSG("\tTTL:\t\t\t%u\n",                ntohl(answer->ttl));
         DEBUG_MSG("\tRD length:\t\t%u\n",            ntohs(answer->rdlength));

         data += sizeof(struct dns_answer);
         rdlength = ntohs(answer->rdlength);

         uint16_t type = ntohs(answer->atype);
         if (type == DNS_TYPE_A || type == DNS_TYPE_AAAA) {
            RecordExtPassiveDNS *rec = new RecordExtPassiveDNS();

            size_t length = name.length();
            if (length >= sizeof(rec->aname)) {
               DEBUG_MSG("Truncating aname (length = %lu) to %lu.\n", length, sizeof(rec->aname) - 1);
               length = sizeof(rec->aname) - 1;
            }
            memcpy(rec->aname, name.c_str(), length);
            rec->aname[length] = 0;

            rec->id = ntohs(dns->id);
            rec->rr_ttl = ntohl(answer->ttl);
            rec->atype = type;

            if (rec->atype == DNS_TYPE_A) {
               // IPv4
               rec->ip.v4 = *(uint32_t *) data;
               parsed_a++;
               rec->ip_version = 4;
            } else {
               // IPv6
               memcpy(rec->ip.v6, data, 16);
               parsed_aaaa++;
               rec->ip_version = 6;
            }

            if (list == NULL) {
               list = rec;
            } else {
               list->addExtension(rec);
            }
         } else if (type == DNS_TYPE_PTR) {
            RecordExtPassiveDNS *rec = new RecordExtPassiveDNS();

            rec->id = ntohs(dns->id);
            rec->rr_ttl = ntohl(answer->ttl);
            rec->atype = type;

            /* Copy domain name. */
            string tmp = get_name(data);
            size_t length = tmp.length();
            if (length >= sizeof(rec->aname)) {
               DEBUG_MSG("Truncating aname (length = %lu) to %lu.\n", length, sizeof(rec->aname) - 1);
               length = sizeof(rec->aname) - 1;
            }
            memcpy(rec->aname, tmp.c_str(), length);
            rec->aname[length] = 0;

            if (!process_ptr_record(name, rec)) {
               delete rec;
            } else {
               parsed_ptr++;
               if (list == NULL) {
                  list = rec;
               } else {
                  list->addExtension(rec);
               }
            }
         }

         data += rdlength;
      }

      DEBUG_MSG("DNS parser quits: parsing done\n\n");
   } catch (const char *err) {
      DEBUG_MSG("%s\n", err);
   }

   return list;
}

/**
 * \brief Provides conversion from string to uint4_t.
 * \param [in] str String representation of value.
 * \param [out] dst Destination variable.
 * \return True on success, false otherwise.
 */
bool PassiveDNSPlugin::str_to_uint4(string str, uint8_t &dst)
{
   char *check;
   errno = 0;
   trim_str(str);
   unsigned long long value = strtoull(str.c_str(), &check, 16);
   if (errno == ERANGE || str[0] == '-' || str[0] == '\0' || *check ||
      value > 15) {
      return false;
   }

   dst = value;
   return true;
}

/**
 * \brief Get IP address from domain name.
 *
 * \param [in] name Domain name string.
 * \param [out] rec Plugin data record.
 * \return True on success, false otherwise.
 */
bool PassiveDNSPlugin::process_ptr_record(string name, RecordExtPassiveDNS *rec)
{
   memset(&rec->ip, 0, sizeof(rec->ip));

   if (name[name.length() - 1] == '.') {
      name.erase(name.length() - 1);
   }

   for (unsigned i = 0; i < name.length(); i++) {
      name[i] = tolower(name[i]);
   }

   string octet;
   string type_str = ".in-addr.arpa";
   size_t type_pos = name.find(type_str);
   size_t begin = 0, end = 0, cnt = 0;
   uint8_t *ip;
   if (type_pos + type_str.length() == name.length()) {
      // IPv4
      name.erase(type_pos);
      rec->ip_version = 4;
      ip = (uint8_t *) &rec->ip.v4;

      while (end != string::npos) {
         end = name.find(".", begin);
         octet = name.substr(begin, (end == string::npos ? (name.length() - begin) : (end - begin)));
         if (cnt > 3 || !str_to_uint8(octet, ip[3 - cnt])) {
            return false;
         }

         cnt++;
         begin = end + 1;
      }
      return cnt == 4;
   } else {
      type_str = ".ip6.arpa";
      type_pos = name.find(type_str);
      if (type_pos + type_str.length() == name.length()) {
         // IPv6
         name.erase(type_pos);
         rec->ip_version = 6;
         ip = (uint8_t *) &rec->ip.v6;

         uint8_t nums[32];
         while (end != string::npos) {
            end = name.find(".", begin);
            octet = name.substr(begin, (end == string::npos ? (name.length() - begin) : (end - begin)));
            if (cnt > 31 || !str_to_uint4(octet, nums[31 - cnt])) {
               return false;
            }

            cnt++;
            begin = end + 1;
         }
         if (cnt != 32) {
            return false;
         }

         for (int i = 0; i < 16; i++) {
            rec->ip.v6[i] = (nums[i] << 4) | nums[i];
         }
         return true;
      }
   }

   return false;
}

/**
 * \brief Add new extension DNS header into Flow.
 * \param [in] data Pointer to packet payload section.
 * \param [in] payload_len Payload length.
 * \param [in] tcp DNS over tcp.
 * \param [out] rec Destination Flow.
 */
int PassiveDNSPlugin::add_ext_dns(const char *data, unsigned int payload_len, bool tcp, Flow &rec)
{
   RecordExt *tmp = parse_dns(data, payload_len, tcp);
   if (tmp != NULL) {
      rec.addExtension(tmp);
   }

   return FLOW_FLUSH;
}

