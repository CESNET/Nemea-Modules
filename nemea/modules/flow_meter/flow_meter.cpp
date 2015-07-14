#include <getopt.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <stdlib.h>
#include <time.h>

#include <libtrap/trap.h>
#include "../../unirec/unirec.h"
#include "../../common/include/nemea-common.h"

#include "flow_meter.h"
#include "packet.h"
#include "flowifc.h"
#include "pcapreader.h"
#include "nhtflowcache.h"
#include "mapflowcache.h"
#include "flowwriter.h"
#include "stats.h"

using namespace std;

inline bool error(const string &e)
{
   cerr << "flowgen: " << e << endl;
   return EXIT_FAILURE;
}

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Flow meter module","Convert packets from PCAP file into flow records.",0,1)

#define MODULE_PARAMS(PARAM) \
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


   int sampling = 100;
   srand(time(NULL));


   // ***** TRAP initialization ***** 
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);


   int opt;
   char* cptr;
   while ((opt = getopt(argc, argv, module_getopt_string)) != -1) {
      switch (opt) {
      case 't':
         cptr = strchr(optarg, ':');
         if (cptr == NULL) {
            return error("Invalid argument for option -t");
         }
         *cptr = '\0';
         options.activetimeout = atof(optarg);
         options.inactivetimeout = atof(cptr+1);
         break;
      case 'p':
         options.payloadlimit = atoi(optarg); break;
      case 'r':
         options.infilename = string(optarg); break;
      case 's':
         options.flowcachesize = atoi(optarg); break;
      case 'S':
         options.statstime = atof(optarg);
         options.statsout = true;
         break;
      case 'm':
         sampling = atoi(optarg);
         break;
      case 'v':
         options.replacementstring = optarg; break;
      case 'V':
         options.verbose = true; break;
      default:
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Invalid arguments");
      }
   }


   if (options.flowcachesize%options.flowlinesize != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Size of flow line (32 by default) must divide size of flow cache.");
   }

   PcapReader packetloader(options);
   if (packetloader.open(options.infilename) != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Can't open input file: "+options.infilename);
   }

   FlowWriter flowwriter(options);
   if (flowwriter.open(options.infilename) != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Couldn't open output file: "+options.infilename+".flow/.data.");
   }

   NHTFlowCache flowcache(options);
   flowcache.set_exporter(&flowwriter);

   if (options.statsout) {
      StatsPlugin stats(options.statstime, cout);
      flowcache.add_plugin(&stats);
   }

   flowcache.init();

   Packet packet;
   int ret;
   while ((ret = packetloader.get_pkt(packet)) == 0 /* && packetloader.cnt_total < 1000 */) {
      if (((rand()%99) +1) <= sampling) {
         flowcache.put_pkt(packet);
      }
   }

   if (ret > 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Error when reading pcap file: "+packetloader.errmsg);
   }

   if (!options.statsout) {
      cout << "Total packets processed: "<< packetloader.cnt_total << endl;
      cout << "Packet headers parsed: "<< packetloader.cnt_parsed << endl;
   }

   flowcache.finish();
   flowwriter.close();
   packetloader.close();

   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return EXIT_SUCCESS;
}
