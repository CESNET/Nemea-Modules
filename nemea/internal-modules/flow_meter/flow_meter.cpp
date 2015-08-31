#include <config.h>
#include <getopt.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <stdlib.h>
#include <time.h>
#include <pcap/pcap.h>

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
#include "fields.c"
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
  PARAM('c', "capture_interface", "Interface to capture from.", required_argument, "string")\
  PARAM('r', "file", "Pcap file to read.", required_argument, "string") \
  PARAM('t', "timeout", "Active and inactive timeout in seconds. Format: FLOAT:FLOAT. (DEFAULT: 300.0:30.0)", required_argument, "string") \
  PARAM('p', "payload", "Collect payload of each flow. NUMBER specifies a limit to collect first NUMBER of bytes. By default do not collect payload.", required_argument, "uint64") \
  PARAM('s', "cache_size", "Size of flow cache in number of flow records. Each flow record has 232 bytes. (DEFAULT: 65536)", required_argument, "uint32") \
  PARAM('S', "statistic", "Print statistics. NUMBER specifies interval between prints.", required_argument, "float") \
  PARAM('m', "sample", "Sampling probability. NUMBER in 100 (DEFAULT: 100)", required_argument, "int32") \
  PARAM('v', "vector", "Replacement vector. 1+32 NUMBERS.", required_argument, "string") \
  PARAM('V', "verbose", "Set verbose mode on.", no_argument, "none")

inline void swapbytes128(char *x)
{
   char tmp;
   for (int i = 0; i < 8; i++) {
      tmp = x[i];
      x[i] = x[15-i];
      x[15-i] = tmp;
   }
}

bool live_verbose;
Packet * packet_ptr;

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
   uint32_t caplen = h->len;
   const u_char * pkt_ptr = bytes;
   uint16_t offset = 0;

   packet_ptr->packetFieldIndicator = 0x0;
   packet_ptr->timestamp = h->ts.tv_sec + h->ts.tv_usec/1000000.0;

   packet_ptr->packetFieldIndicator |= PCKT_TIMESTAMP;

   uint16_t ether_type = ((uint8_t)(bytes[12]) << 8) | (uint8_t)bytes[13];

   if (ether_type == ETHER_TYPE_IPv4 || ether_type == ETHER_TYPE_IPv6) {
      offset = 14;
   } else if (ether_type == ETHER_TYPE_8021Q) {
      offset = 18;
   } else {
      if (live_verbose) {
         fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);
      }
      return;
   }

   pkt_ptr += offset;
   if (ether_type ==  ETHER_TYPE_IPv4 || ether_type == ETHER_TYPE_8021Q) {
      ipv4hdr *ip_hdr = (ipv4hdr*) pkt_ptr;
      pkt_ptr += (ip_hdr->ver_hdrlen & 0x0f)*4;

      packet_ptr->ipVersion                = (ip_hdr->ver_hdrlen & 0xf0) >> 4;
      packet_ptr->protocolIdentifier       = ip_hdr->protocol;
      packet_ptr->ipClassOfService         = ip_hdr->tos;
      packet_ptr->ipLength                 = ntohs(ip_hdr->tot_len);
      packet_ptr->ipTtl                    = ip_hdr->ttl;
      packet_ptr->sourceIPv4Address        = ntohl(ip_hdr->saddr);
      packet_ptr->destinationIPv4Address   = ntohl(ip_hdr->daddr);

      packet_ptr->packetFieldIndicator |= PCKT_IPV4_MASK;

   } else if (ether_type == ETHER_TYPE_IPv6) {
      ipv6hdr *ip_hdr = (ipv6hdr*) pkt_ptr;
      pkt_ptr += 40;

      packet_ptr->ipVersion = (ip_hdr->v6nfo & 0xf0000000) >> 28;
      packet_ptr->ipClassOfService = (ip_hdr->v6nfo & 0x0ff00000) >> 20;
      packet_ptr->protocolIdentifier = ip_hdr->next_hdr;
      packet_ptr->ipLength = ntohs(ip_hdr->payload_len);
      memcpy(packet_ptr->sourceIPv6Address, ip_hdr->saddr, 16);
      memcpy(packet_ptr->destinationIPv6Address, ip_hdr->daddr, 16);

      swapbytes128(packet_ptr->sourceIPv6Address);
      swapbytes128(packet_ptr->destinationIPv6Address);

      packet_ptr->packetFieldIndicator |= PCKT_IPV6_MASK;
   }

   if (packet_ptr->protocolIdentifier == IP_PROTO_TCP) {
      tcphdr *tcp_hdr = (tcphdr*)pkt_ptr;
      pkt_ptr += ((tcp_hdr->doff & 0xf0) >> 4)*4;

      packet_ptr->sourceTransportPort      = ntohs(tcp_hdr->source);
      packet_ptr->destinationTransportPort = ntohs(tcp_hdr->dest);
      packet_ptr->tcpControlBits           = tcp_hdr->flags;
      packet_ptr->packetFieldIndicator |= PCKT_TCP_MASK;
   }
   else if (packet_ptr->protocolIdentifier == IP_PROTO_UDP) {
      udphdr *udp_hdr = (udphdr *)pkt_ptr;
      pkt_ptr += 8;

      packet_ptr->sourceTransportPort      = ntohs(udp_hdr->source);
      packet_ptr->destinationTransportPort = ntohs(udp_hdr->dest);
      packet_ptr->packetFieldIndicator |= PCKT_UDP_MASK;
   } else if (packet_ptr->protocolIdentifier == IP_PROTO_ICMP || packet_ptr->protocolIdentifier == IP_PROTO_ICMPv6) {
      pkt_ptr += 8;
   } else {
      if (live_verbose) {
         fprintf(stderr, "Unknown protocol, %d, skipping...\n", packet_ptr->protocolIdentifier);
      }
      return;
   }

   if ( ((packet_ptr->packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) ||
   ((packet_ptr->packetFieldIndicator & PCKT_UDP_MASK) == PCKT_UDP_MASK) ) {
      packet_ptr->transportPayloadPacketSectionSize = caplen - (pkt_ptr - bytes);

      if (packet_ptr->transportPayloadPacketSectionSize > MAXPCKTPAYLOADSIZE) {
         if (live_verbose) {
            fprintf(stderr, "Payload too long: %d, trimming to: %d\n", packet_ptr->transportPayloadPacketSectionSize, MAXPCKTPAYLOADSIZE);
         }
         packet_ptr->transportPayloadPacketSectionSize = MAXPCKTPAYLOADSIZE;
      }
      memcpy(packet_ptr->transportPayloadPacketSection, pkt_ptr, packet_ptr->transportPayloadPacketSectionSize);
      packet_ptr->packetFieldIndicator |= PCKT_PAYLOAD_MASK;
   }

}


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

   pcap_t *pc = NULL;
   string source_iface = "";
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
         source_iface = string(optarg);
         break;
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
         options.infilename = string(optarg);break;
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

   live_verbose = options.verbose;
   if (source_iface != "" && options.infilename != "") {
      return error("Cannot capture from file and from interface at the same time.");
   } else if (source_iface == "" && options.infilename == "") {
      return error("Neither capture interface nor input file is specified.");
   }

   if (options.flowcachesize%options.flowlinesize != 0) {
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return error("Size of flow line (32 by default) must divide size of flow cache.");
   }

   char errbuf[PCAP_ERRBUF_SIZE];
   PcapReader packetloader(options);
   if (source_iface == "") {
      if (packetloader.open(options.infilename) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Can't open input file: "+options.infilename);
      }
   } else {
      pc = pcap_create(source_iface.c_str(), errbuf);
      if (pc == NULL) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Unable to initialize libpcap.");
      }

      if (pcap_activate(pc) != 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
          pcap_close(pc);
         return error(pcap_geterr(pc));
      }
   }

   FlowWriter flowwriter(options);
   if (flowwriter.open(options.infilename) != 0) {
      if (source_iface != "") {
         pcap_close(pc);
      } else {
         packetloader.close();
   }

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

   if(source_iface == "") {
      while ((ret = packetloader.get_pkt(packet)) == 0 /* && packetloader.cnt_total < 1000 */) {
         if (((rand()%99) +1) <= sampling) {
            flowcache.put_pkt(packet);
         }
      }

      if (ret > 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return error("Error when reading pcap file: "+packetloader.errmsg);
      }
   } else {
      packet_ptr = &packet;
      while ((ret = pcap_dispatch(pc, 0, packet_handler, NULL)) >= 0) {
         if (ret > 0) {
            flowcache.put_pkt(packet);
         }
      }
      if (ret < 0) {
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         pcap_close(pc);
         return error(pcap_geterr(pc));
      }
   }

   if (!options.statsout) {
      cout << "Total packets processed: "<< packetloader.cnt_total << endl;
      cout << "Packet headers parsed: "<< packetloader.cnt_parsed << endl;
   }

   flowcache.finish();
   flowwriter.close();
   if (source_iface == "") {
      packetloader.close();
   } else {
      pcap_close(pc);
   }

   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return EXIT_SUCCESS;
}
