/**
 * \file flow_meter.cpp
 * \brief Main file of the flow_meter module.
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


#include <config.h>
#include <getopt.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <stdlib.h>
#include <time.h>

#include "flow_meter.h"
#include "packet.h"
#include "flowifc.h"
#include "pcapreader.h"
#include "nhtflowcache.h"
#include "unirecexporter.h"
#include "stats.h"
#include "fields.h"

#include "httpplugin.h"
#include "dnsplugin.h"
#include "sipplugin.h"

using namespace std;

/**
 * \brief Print an error message.
 * \param [in] e String containing an error message
 * \return EXIT_FAILURE
 */
inline bool error(const string &e)
{
   cerr << "flow_meter: " << e << endl;
   return EXIT_FAILURE;
}

trap_module_info_t *module_info = NULL;

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint8 TOS,
   uint8 TTL
)

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Flow meter module", "Convert packets from PCAP file or network interface into flow records.", 0, -1)

#define MODULE_PARAMS(PARAM) \
  PARAM('p', "plugins", "Activate specified parsing plugins. Output interface for each plugin correspond the order which you specify items in -i and -p param. "\
  "For example: \'-i u:a,u:b,u:c -p http,basic,dns\' http traffic will be send to interface u:a, basic flow to u:b etc. If you don't specify -p parameter, flow meter"\
  "will require one output interface for basic flow by default. Format: plugin_name[,...] Supported plugins: http,dns,sip,basic", required_argument, "string")\
  PARAM('c', "count", "Quit after number of packets are captured.", required_argument, "uint32")\
  PARAM('I', "interface", "Capture from given network interface. Parameter require interface name (eth0 for example).", required_argument, "string")\
  PARAM('r', "file", "Pcap file to read.", required_argument, "string") \
  PARAM('t', "timeout", "Active and inactive timeout in seconds. Format: FLOAT:FLOAT. (DEFAULT: 300.0:30.0)", required_argument, "string") \
  PARAM('s', "cache_size", "Size of flow cache in number of flow records. Each flow record has 232 bytes. (DEFAULT: 65536)", required_argument, "uint32") \
  PARAM('S', "statistic", "Print statistics. NUMBER specifies interval between prints.", required_argument, "float") \
  PARAM('m', "sample", "Sampling probability. NUMBER in 100 (DEFAULT: 100)", required_argument, "int32") \
  PARAM('V', "vector", "Replacement vector. 1+32 NUMBERS.", required_argument, "string") \
  PARAM('v', "verbose", "Set verbose mode on.", no_argument, "none")

/**
 * \brief Parse input plugin settings.
 * \param [in] settings String containing input plugin settings.
 * \param [out] plugins Array for storing active plugins.
 * \param [in] module_options Options for plugin initialization.
 * \return Number of items specified in input string.
 */
int parse_plugin_settings(const string &settings, vector<FlowCachePlugin *> &plugins, options_t &module_options)
{
   string proto;
   size_t begin = 0, end = 0;

   int ifc_num = 0;
   while (end != string::npos) { // Iterate through user specified settings.
      end = settings.find(",", begin);
      proto = settings.substr(begin, (end == string::npos ? (settings.length() - begin) : (end - begin)));

      if (proto == "basic") {
         module_options.basic_ifc_num = ifc_num++; // Enable parsing basic flow (flow without any plugin output).
      } else if (proto == "http") {
         vector<plugin_opt> tmp;
         // Register extension header identifiers.
         // New configuration support sending plugin output to specific libtrap interface (e.g. http to ifc 1, dns to ifc 2...)
         // so it is necessary store extension-header -> output interface mapping within plugin.

         tmp.push_back(plugin_opt("http-req", http_request, ifc_num));
         tmp.push_back(plugin_opt("http-resp", http_response, ifc_num++));

         plugins.push_back(new HTTPPlugin(module_options, tmp));
      } else if (proto == "dns"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("dns", dns, ifc_num++));

         plugins.push_back(new DNSPlugin(module_options, tmp));
      } else if (proto == "sip"){
         vector<plugin_opt> tmp;
         tmp.push_back(plugin_opt("sip", sip, ifc_num++));

         plugins.push_back(new SIPPlugin(module_options, tmp));
      } else {
         fprintf(stderr, "Unsupported plugin: \"%s\"\n", proto.c_str());
         return -1;
      }
      begin = end + 1;
   }

   return ifc_num;
}

/**
 * \brief Count ifc interfaces.
 * \param [in] argc Number of parameters.
 * \param [in] argv Pointer to parameters.
 * \return Number of ifc interfaces.
 */
int count_ifc_interfaces(int argc, char *argv[])
{
   char *interfaces = NULL;
   for (int i = 1; i < argc; i++) { // Find argument for param -i.
      if (!strcmp(argv[i], "-i") && i + 1 < argc) {
         interfaces = argv[i + 1];
      }
   }

   int int_cnt = 1;
   if (interfaces != NULL) {
      while(*interfaces) { // Count number of specified interfaces.
         if (*(interfaces++) == ',') {
            int_cnt++;
         }
      }
      return int_cnt;
   }

   return int_cnt;
}

int main(int argc, char *argv[])
{
   plugins_t plugin_wrapper;
   options_t options;
   options.flowcachesize = DEFAULT_FLOW_CACHE_SIZE;
   options.flowlinesize = DEFAULT_FLOW_LINE_SIZE;
   options.inactivetimeout = DEFAULT_INACTIVE_TIMEOUT;
   options.activetimeout = DEFAULT_ACTIVE_TIMEOUT;
   options.replacementstring = DEFAULT_REPLACEMENT_STRING;
   options.statsout = false;
   options.verbose = false;
   options.interface = "";
   options.basic_ifc_num = 0;

   uint32_t pkt_limit = 0; // Limit of packets for packet parser. 0 = no limit
   int sampling = 100;
   srand(time(NULL));

   // ***** TRAP initialization *****
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
   module_info->num_ifc_out = count_ifc_interfaces(argc, argv);
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   for (int i = 0; i < module_info->num_ifc_out; i++) {
      trap_ifcctl(TRAPIFC_OUTPUT, i, TRAPCTL_SETTIMEOUT, TRAP_WAIT);
   }

   int opt;
   char *cptr;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'p':
         {
            options.basic_ifc_num = -1;
            int ret = parse_plugin_settings(string(optarg), plugin_wrapper.plugins, options);
            if (ret < 0) {
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
               return error("Invalid argument for option -p");
            }
            if (ret != module_info->num_ifc_out) {
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               TRAP_DEFAULT_FINALIZATION();
               return error("Number of output ifc interfaces does not correspond number of items in -p parameter.");
            }
         }
         break;
      case 'c':
         pkt_limit = strtoul(optarg, NULL, 10);
         break;
      case 'I':
         options.interface = string(optarg);
         break;
      case 't':
         cptr = strchr(optarg, ':');
         if (cptr == NULL) {
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return error("Invalid argument for option -t");
         }
         *cptr = '\0';
         options.activetimeout = atof(optarg);
         options.inactivetimeout = atof(cptr + 1);
         break;
      case 'r':
         options.infilename = string(optarg);
         break;
      case 's':
         options.flowcachesize = atoi(optarg);
         break;
      case 'S':
         options.statstime = atof(optarg);
         options.statsout = true;
         break;
      case 'm':
         sampling = atoi(optarg);
         if (sampling < 0 || sampling > 100) {
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return error("Invalid argument for option -m: interval needs to be between 0-100");
         }
         break;
      case 'V':
         options.replacementstring = optarg;
         break;
      case 'v':
         options.verbose = true;
         break;
      default:
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return error("Invalid arguments");
      }
   }

   if (options.interface != "" && options.infilename != "") {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return error("Cannot capture from file and from interface at the same time.");
   } else if (options.interface == "" && options.infilename == "") {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return error("Specify capture interface (-I) or file for reading (-r). ");
   }

   if (options.flowcachesize % options.flowlinesize != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return error("Size of flow line (32 by default) must divide size of flow cache.");
   }

   PcapReader packetloader(options);
   if (options.interface == "") {
      if (packetloader.open_file(options.infilename) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return error("Can't open input file: " + options.infilename);
      }
   } else {
      if (packetloader.init_interface(options.interface) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return error("Unable to initialize libpcap: " + packetloader.errmsg);
      }
   }

   NHTFlowCache flowcache(options);
   UnirecExporter flowwriter;

   if (flowwriter.init(plugin_wrapper.plugins, module_info->num_ifc_out, options.basic_ifc_num) != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return error("Unable to initialize UnirecExporter.");
   }
   flowcache.set_exporter(&flowwriter);

   for (unsigned int i = 0; i < plugin_wrapper.plugins.size(); i++) {
      flowcache.add_plugin(plugin_wrapper.plugins[i]);
   }

   if (options.statsout) {
      StatsPlugin stats(options.statstime, cout);
      flowcache.add_plugin(&stats);
   }

   flowcache.init();

   Packet packet;
   int ret;
   uint32_t pkt_total = 0, pkt_parsed = 0;
   packet.packet = new char[MAXPCKTSIZE + 1];

   // Main packet capture loop.
   while ((ret = packetloader.get_pkt(packet)) > 0) {
      if (ret == 2 && (sampling == 100 || ((rand() % 99) +1) <= sampling)) {
         flowcache.put_pkt(packet);
         pkt_parsed++;
      }
      pkt_total++;

      // Check if packet limit is reached.
      if (pkt_limit != 0 && pkt_parsed >= pkt_limit) {
         break;
      }
   }

   if (ret < 0) {
      packetloader.close();
      flowwriter.close();
      delete [] packet.packet;
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return error("Error during reading: " + packetloader.errmsg);
   }

   if (!options.statsout) {
      cout << "Total packets processed: "<< pkt_total << endl;
      cout << "Packet headers parsed: "<< pkt_parsed << endl;
   }

   // Cleanup
   flowcache.finish();
   flowwriter.close();
   packetloader.close();

   delete [] packet.packet;
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
   TRAP_DEFAULT_FINALIZATION();

   return EXIT_SUCCESS;
}
