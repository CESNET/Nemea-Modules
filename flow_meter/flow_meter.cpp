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

#include <libtrap/trap.h>

#include <unirec/unirec.h>
#include <nemea-common.h>

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
  BASIC("Flow meter module", "Convert packets from PCAP file or live capture into flow records.", 0, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('p', "plugins", "Activate specified parsing plugins.. Format: plugin_name[,...] Supported plugins: http,dns", required_argument, "string")\
  PARAM('c', "count", "Quit after n packets are captured.", required_argument, "uint32")\
  PARAM('I', "interface", "Name of capture interface. (eth0 for example)", required_argument, "string")\
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
 * \param [in] options Options for plugin initialization.
 * \return True if setting was parsed, false if an error occured.
 */
bool parse_plugin_settings(const std::string &settings, std::vector<FlowCachePlugin *> &plugins, const options_t &options)
{
   std::string proto;
   size_t begin = 0, end = 0;

   while (end != std::string::npos) {
      end = settings.find(",", begin);
      proto = settings.substr(begin, (end == std::string::npos ? (settings.length() - begin) : (end - begin)));

      if (proto == "http") {
         plugins.push_back(new HTTPPlugin(options));
      } else if (proto == "dns"){
         plugins.push_back(new DNSPlugin(options));
      } else {
         fprintf(stderr, "Unsupported plugin: \"%s\"\n", proto.c_str());
         return false;
      }
      begin = end + 1;
   }

   return true;
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

   uint32_t pkt_limit = 0;
   int sampling = 100;
   srand(time(NULL));

   // ***** TRAP initialization *****
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_WAIT);

   int opt;
   char *cptr;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'p':
         if (!parse_plugin_settings(string(optarg), plugin_wrapper.plugins, options)) {
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return error("Invalid argument for option -p");
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
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
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
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
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
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Invalid arguments");
      }
   }

   if (options.interface != "" && options.infilename != "") {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Cannot capture from file and from interface at the same time.");
   } else if (options.interface == "" && options.infilename == "") {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Neither capture interface nor input file specified.");
   }

   if (options.flowcachesize % options.flowlinesize != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Size of flow line (32 by default) must divide size of flow cache.");
   }

   PcapReader packetloader(options);
   if (options.interface == "") {
      if (packetloader.open_file(options.infilename) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Can't open input file: " + options.infilename);
      }
   } else {
      if (packetloader.init_interface(options.interface) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Unable to initialize libpcap: " + packetloader.errmsg);
      }
   }

   NHTFlowCache flowcache(options);
   UnirecExporter flowwriter;

   if (flowwriter.init(plugin_wrapper.plugins) != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
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

   while ((ret = packetloader.get_pkt(packet)) > 0) {
      if (ret == 2 && (sampling == 100 || ((rand() % 99) +1) <= sampling)) {
         flowcache.put_pkt(packet);
         pkt_parsed++;
      }
      pkt_total++;

      if (pkt_limit != 0 && pkt_parsed >= pkt_limit) {
         break;
      }
   }

   if (ret < 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      packetloader.close();
      return error("Error during reading: " + packetloader.errmsg);
   }

   if (!options.statsout) {
      cout << "Total packets processed: "<< pkt_total << endl;
      cout << "Packet headers parsed: "<< pkt_parsed << endl;
   }

   flowcache.finish();
   flowwriter.close();
   packetloader.close();

   delete [] packet.packet;

   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return EXIT_SUCCESS;
}
