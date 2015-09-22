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
#include "mapflowcache.h"
#include "unirecexporter.h"
#include "stats.h"
#include "fields.c"
#include "httpplugin.h"

using namespace std;

inline bool error(const string &e)
{
   cerr << "flowgen: " << e << endl;
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
  BASIC("Flow meter module","Convert packets from PCAP file into flow records.",0,1)

#define MODULE_PARAMS(PARAM) \
  PARAM('c', "count", "Quit after n packets are captured.", required_argument, "uint32")\
  PARAM('I', "interface", "Name of capture interface. (eth0 for example)", required_argument, "string")\
  PARAM('r', "file", "Pcap file to read.", required_argument, "string") \
  PARAM('t', "timeout", "Active and inactive timeout in seconds. Format: FLOAT:FLOAT. (DEFAULT: 300.0:30.0)", required_argument, "string") \
  PARAM('p', "payload", "Collect payload of each flow. NUMBER specifies a limit to collect first NUMBER of bytes. By default do not collect payload.", required_argument, "uint64") \
  PARAM('s', "cache_size", "Size of flow cache in number of flow records. Each flow record has 232 bytes. (DEFAULT: 65536)", required_argument, "uint32") \
  PARAM('S', "statistic", "Print statistics. NUMBER specifies interval between prints.", required_argument, "float") \
  PARAM('m', "sample", "Sampling probability. NUMBER in 100 (DEFAULT: 100)", required_argument, "int32") \
  PARAM('v', "vector", "Replacement vector. 1+32 NUMBERS.", required_argument, "string") \
  PARAM('V', "verbose", "Set verbose mode on.", no_argument, "none")


int main(int argc, char *argv[])
{
   options_t options;
   options.flowcachesize = DEFAULT_FLOW_CACHE_SIZE;
   options.flowlinesize = DEFAULT_FLOW_LINE_SIZE;
   options.inactivetimeout = DEFAULT_INACTIVE_TIMEOUT;
   options.activetimeout = DEFAULT_ACTIVE_TIMEOUT;
   options.payloadlimit = DEFAULT_PAYLOAD_LIMIT;
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
   char* cptr;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'c':
         pkt_limit = strtoul(optarg, NULL, 10);
         break;
      case 'I':
         options.interface = string(optarg);
         break;
      case 't':
         cptr = strchr(optarg, ':');
         if (cptr == NULL) {
            return error("Invalid argument for option -t");
         }
         *cptr = '\0';
         options.activetimeout = atof(optarg);
         options.inactivetimeout = atof(cptr + 1);
         break;
      case 'p':
         options.payloadlimit = atoi(optarg);
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
         break;
      case 'v':
         options.replacementstring = optarg;
         break;
      case 'V':
         options.verbose = true;
         break;
      default:
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Invalid arguments");
      }
   }

   if (options.interface != "" && options.infilename != "") {
      return error("Cannot capture from file and from interface at the same time.");
   } else if (options.interface == "" && options.infilename == "") {
      return error("Neither capture interface nor input file specified.");
   }

   if (options.flowcachesize%options.flowlinesize != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Size of flow line (32 by default) must divide size of flow cache.");
   }

   PcapReader packetloader(options);
   if (options.interface == "") {
      if (packetloader.open_file(options.infilename) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Can't open input file: "+options.infilename);
      }
   } else {
      if (packetloader.init_interface(options.interface) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Unable to initialize libpcap: "+packetloader.errmsg);
      }
   }

   UnirecExporter flowwriter(options);
   if (flowwriter.open(options.infilename) != 0) {
      packetloader.close();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Couldn't open output file: "+options.infilename+".flow/.data.");
   }

   NHTFlowCache flowcache(options);
   flowcache.set_exporter(&flowwriter);

   //HTTPPlugin http(options);
   //flowcache.add_plugin(&http);

   if (options.statsout) {
      StatsPlugin stats(options.statstime, cout);
      flowcache.add_plugin(&stats);
   }

   flowcache.init();
   Packet packet;
   int ret;
   uint32_t pkt_total = 0, pkt_parsed = 0;
   packet.transportPayloadPacketSection = new char[MAXPCKTPAYLOADSIZE + 1];

   while ((ret = packetloader.get_pkt(packet)) > 0) {
      if (packet.packetFieldIndicator & PCKT_VALID && ((rand() % 99) +1) <= sampling) {
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
   //http.close();
   packetloader.close();
   delete [] packet.transportPayloadPacketSection;

   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return EXIT_SUCCESS;
}
