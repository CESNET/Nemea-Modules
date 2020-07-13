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
      SSDP_DEBUG_MSG("SSDP post create\n");
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

void SSDPPlugin::parse_ssdp_message(Flow &rec, const Packet &pkt){
   const char* data = (const char*) pkt.payload;
   SSDP_DEBUG_MSG("%s", data);
   const char *i = strcasestr(data, "NOTIFY");
   if(i){
      SSDP_DEBUG_MSG("Found notify\n");
   }
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

