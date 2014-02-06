#include <getopt.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>

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

trap_module_info_t module_info = {
   "Flow meter module", // Module name
   // Module description
   "Exports PCAP file via TRAP interface.\n"
   "Parameters:\n"
   "  -a NUMBER         Active timeout. (DEFAULT: 30.0)\n"
   "  -i NUMBER         Inactive timeout. (DEFAULT: 5.0)\n"
   "  -p NUMBER         Collect payload of each flow.\n"
   "  -r FILENAME       Pcap file to read.\n"
   "                    NUMBER specifies a limit to collect first NUMBER of bytes.\n"
   "                    By default do not collect payload.\n"
   "  -s NUMBER         Size of flow cache. (DEFAULT: 8192)\n"
   "  -S NUMBER         Print statistics.\n"
   "                    NUMBER specifies interval between prints(DEFAULT: 1.0)\n"
   "  -m NUMBER         Sampling probability. NUMBER in 100 (DEFAULT: 100)\n"
// "  -m STRING         Sampling probability ex: 1..100 is 1 in 100. (NOT IMPLEMENTED)\n"
// "  -t NUMBER         Sampling type. (NOT IMPLEMENTED)\n"
   "  -v STRING         Replacement vector. 1+32 NUMBERS.\n"
   "Interfaces:\n"
   "   Input:  0 (PCAP file)"
   "   Output: 1 (COLLECTOR_FLOW)",
   0, // Number of input interfaces
   1, // Number of output interfaces
};


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
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);


   int opt;
   while ((opt = getopt(argc, argv, "a:i:p:r:s:S:m:v:Vw:")) != -1) {
      switch (opt) {
      case 'a':
         options.activetimeout = atof(optarg); break;
      case 'i':
         options.inactivetimeout = atof(optarg); break;
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
         return error("Invalid arguments");
      }
   }


   if (options.flowcachesize%options.flowlinesize != 0)
      return error("Size of flow line (32 by default) must divide size of flow cache.");

   PcapReader packetloader(options);
   if (packetloader.open(options.infilename) != 0)
      return error("Can't open input file: "+options.infilename);

   FlowWriter flowwriter(options);
   if (flowwriter.open(options.infilename) != 0)
      return error("Couldn't open output file: "+options.infilename+".flow/.data.");

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

   if (ret > 0)
      return error("Error when reading pcap file: "+packetloader.errmsg);

   if (!options.statsout) {
      cout << "Total packets processed: "<< packetloader.cnt_total << endl;
      cout << "Packet headers parsed: "<< packetloader.cnt_parsed << endl;
   }

   flowcache.finish();
   flowwriter.close();
   packetloader.close();

   return EXIT_SUCCESS;
}
