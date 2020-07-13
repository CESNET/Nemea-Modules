/**
 * \file ssdpplugin.cpp
 * \brief Plugin for parsing ssdp traffic.
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

#include <iostream>

#include "ssdpplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

using namespace std;

#define DEBUG_SSDP

// Print debug message if debugging is allowed.
#ifdef DEBUG_SSDP
#define SSDP_DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define SSDP_DEBUG_MSG(format, ...)
#endif

#define SSDP_UNIREC_TEMPLATE "SSDP_URN,SSDP_SERVER,SSDP_USER_AGENT"

UR_FIELDS (
   string SSDP_URN,
   string SSDP_SERVER,
   string SSDP_USER_AGENT
)

enum header_types {
   LOCATION,
   NT,
   ST,
   SERVER,
   NONE
};

const char *headers[]= {
   "location",
   "nt",
   "st",
   "server"
};

SSDPPlugin::SSDPPlugin(const options_t &module_options)
{
   record = NULL;
   print_stats = module_options.print_stats;
}

SSDPPlugin::SSDPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   record = NULL;
   print_stats = module_options.print_stats;
}

int SSDPPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int SSDPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   if (pkt.dst_port == 1900){
      record = new RecordExtSSDP();
      rec.addExtension(record);
      record = NULL;
      
      parse_ssdp_message(rec, pkt);
   }
   return 0;
}

int SSDPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   if (pkt.dst_port == 1900){
      parse_ssdp_message(rec, pkt);
   }
   return 0;
}

int SSDPPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void SSDPPlugin::pre_export(Flow &rec)
{
}

void SSDPPlugin::finish()
{
   if (print_stats) {
      cout << "SSDP plugin stats:" << endl;
   }
}

/**
 * \brief Parses port from location header message string
 */
int SSDPPlugin::parse_loc_port(char **data, uint8_t ip_version){
   int port;
   char *end_ptr = NULL;
   if(ip_version == 6){
      while(**data){
         if(*(*data)++ == ']'){
            (*data)++;
            break;
         }
      }
   }
   else {
      while (**data){
         if(*(*data)++ == '.'){
            break;
         }
      }
      while(**data){
         if(*(*data)++ == ':'){
            break;     
         }
      }
   }
   port = strtol(*data, &end_ptr, 0);
   if(*data != end_ptr){
      return port;
   }
   else {
      return -1;
   }
}

/**
 * \brief Checks for given header string in data
 */
bool SSDPPlugin::get_header_val(char **data, const char* header, const int len){
   if(strncasecmp(*data, header, len) == 0 &&
      (*data)[len] == ':'){
      (*data) += len + 1;
      while(isspace(**data)){
         (*data)++;
      };
      return true;
   }
   return false;
}

/**
 * \brief Parses one line of SSDP payload
 */
void SSDPPlugin::get_headers(char **data, int n, const char *headers[], uint8_t ip_version){
   for(int i = 0; i < n; i++){
      if (get_header_val(data, headers[i], strlen(headers[i]))){
         int port = 0;
         switch ((header_types) i)
         {
            case NT:
            case ST:
               if(get_header_val(data, "urn", strlen("urn"))){
                  SSDP_DEBUG_MSG("%s\n", *data);
               }
               break;
            case LOCATION:
               port = parse_loc_port(data, ip_version);
               if (port > 0){
                  SSDP_DEBUG_MSG("%d\n", port);
               }
               break;
            case SERVER:
               SSDP_DEBUG_MSG("%s\n", *data);
               break;
            default:
               break;         
         }
         break;
      }
   }
   return;
}

/**
 * \brief Appends a value to the existing csv entry.
 */
void SSDPPlugin::append_value(char *curr_entry, char *value){
   // TODO
}

/**
 * \brief Parses SSDP notify payload.
 */
const char *SSDPPlugin::parse_notify(const char *data, Flow &rec, RecordExtSSDP *ext){
   char *tmp_old = (char *)data;
   char *tmp = tmp_old;
   while (*tmp != '\0'){
      if (*tmp == '\n'){
         *tmp = '\0';
         get_headers(&tmp_old, 4, headers, rec.ip_version);
         tmp_old = tmp + 1;
      }
      tmp++;
   }
   return data;
}

/**
 * \brief Parses SSDP payload.
 */
void SSDPPlugin::parse_ssdp_message(Flow &rec, const Packet &pkt){
   const char* data = (const char*) pkt.payload;
   RecordExtSSDP *ext = NULL;
   ext = dynamic_cast<RecordExtSSDP *>(rec.getExtension(ssdp));
   if(data[0] == 'N'){
      SSDP_DEBUG_MSG("Notify\n");
      parse_notify(data, rec, ext);
   }
   else if (data[0] == 'M'){
      SSDP_DEBUG_MSG("M-search\n");
   }
   SSDP_DEBUG_MSG("\n");
}

const char *ipfix_ssdp_template[] = {
   IPFIX_SSDP_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **SSDPPlugin::get_ipfix_string()
{
   return ipfix_ssdp_template;
}

string SSDPPlugin::get_unirec_field_string()
{
   return SSDP_UNIREC_TEMPLATE;
}

bool SSDPPlugin::include_basic_flow_fields()
{
   return true;
}

