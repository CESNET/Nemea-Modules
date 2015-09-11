#include "pcapreader.h"
#include <cstdio>
#include <cstring>
#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

using namespace std;

inline void swapbytes128(char *x)
{
   char tmp;
   for (int i = 0; i < 8; i++) {
      tmp = x[i];
      x[i] = x[15-i];
      x[15-i] = tmp;
   }
}

void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data)
{
   Packet &pkt = *(Packet *)arg;
   struct ethhdr *eth = (struct ethhdr *) data;
   uint8_t transport_proto = 0x0;
   int payload_len = 0x0;

   uint16_t ethertype = ntohs(eth->h_proto);
   if (ethertype == ETH_P_8021Q) {
      data += 18;
      ethertype = ntohs(data[-2]);
   } else {
      data += 14;
   }

   pkt.packetFieldIndicator = 0x0;
   pkt.timestamp = h->ts.tv_sec + h->ts.tv_usec/1000000.0;

   if (ethertype == ETH_P_IP) {
      struct iphdr *ip = (struct iphdr *) (data);

      pkt.ipVersion = ip->version;
      pkt.protocolIdentifier = ip->protocol;
      pkt.ipClassOfService = ip->tos;
      pkt.ipLength = ntohs(ip->tot_len);
      pkt.ipTtl = ip->ttl;
      pkt.sourceIPv4Address = ntohl(ip->saddr);
      pkt.destinationIPv4Address = ntohl(ip->daddr);
      pkt.packetFieldIndicator |= PCKT_IPV4_MASK;

      transport_proto = ip->protocol;
      payload_len = ntohs(ip->tot_len) - ip->ihl * 4;
      data += ip->ihl * 4;

   } else if (ethertype == ETH_P_IPV6) {
      struct ip6_hdr *ip6 = (struct ip6_hdr *) (data);

      pkt.ipVersion = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28;
      pkt.ipClassOfService = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20;
      pkt.protocolIdentifier = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      pkt.ipLength = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
      memcpy(pkt.sourceIPv6Address, (const char *)&ip6->ip6_src, 16);
      memcpy(pkt.destinationIPv6Address, (const char *)&ip6->ip6_dst, 16);
      pkt.packetFieldIndicator |= PCKT_IPV6_MASK;

      swapbytes128(pkt.sourceIPv6Address);
      swapbytes128(pkt.destinationIPv6Address);

      transport_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      payload_len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);   //TODO: IPv6 Extension header
      data += 40;

   } else {
      fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ethertype);
      return;
   }


   if (transport_proto == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *) (data);

      pkt.sourceTransportPort = ntohs(tcp->source);
      pkt.destinationTransportPort = ntohs(tcp->dest);
      pkt.tcpControlBits = 0x0;
      if (tcp->fin) {
         pkt.tcpControlBits |= TCP_FIN;
      }
      if (tcp->syn) {
         pkt.tcpControlBits |= TCP_SYN;
      }
      if (tcp->rst) {
         pkt.tcpControlBits |= TCP_RST;
      }
      if (tcp->psh) {
         pkt.tcpControlBits |= TCP_PUSH;
      }
      if (tcp->ack) {
         pkt.tcpControlBits |= TCP_ACK;
      }
      if (tcp->urg) {
         pkt.tcpControlBits |= TCP_URG;
      }
      pkt.packetFieldIndicator |= PCKT_TCP_MASK;

      data += tcp->doff * 4;
      payload_len -= tcp->doff * 4;

   } else if (transport_proto == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *) (data);

      pkt.sourceTransportPort = ntohs(udp->source);
      pkt.destinationTransportPort = ntohs(udp->dest);
      pkt.packetFieldIndicator |= PCKT_UDP_MASK;

      data += 8;
      payload_len -= 8;

   } else if (transport_proto == IPPROTO_ICMP) {
      struct icmphdr *icmp = (struct icmphdr *) (data);

   } else if (transport_proto == IPPROTO_ICMPV6) {
      struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (data);

   } else {
      fprintf(stderr, "Unknown protocol\n");
      return;
   }

   if (((pkt.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) ||
       ((pkt.packetFieldIndicator & PCKT_UDP_MASK) == PCKT_UDP_MASK)) {
      pkt.transportPayloadPacketSectionSize = payload_len;
      pkt.transportPayloadPacketSection = (const char*)data;
      pkt.packetFieldIndicator |= PCKT_PAYLOAD_MASK;
   }

   pkt.packetFieldIndicator |= PCKT_VALID;
}


PcapReader::PcapReader() : handle(NULL)
{
}

PcapReader::PcapReader(options_t &options) : handle(NULL)
{
}

PcapReader::~PcapReader()
{
   this->close();
}

int PcapReader::open_file(const std::string &file)
{
   if (handle != NULL) {
      errmsg = "Interface or pcap file is already opened.";
      return 1;
   }

   char errbuf[PCAP_ERRBUF_SIZE];
   handle = pcap_open_offline(file.c_str(), errbuf);
   if (handle == NULL) {
      errmsg = errbuf;
      return 2;
   }

   errmsg = "";
   return 0;
}

int PcapReader::init_interface(const std::string &interface)
{
   if (handle != NULL) {
      errmsg = "Interface or pcap file is already opened.";
      return 1;
   }

   char errbuf[PCAP_ERRBUF_SIZE];
   handle = pcap_create(interface.c_str(), errbuf);
   if (handle == NULL) {
      errmsg = errbuf;
      return 2;
   }

   if (pcap_activate(handle) != 0) {
      errmsg = pcap_geterr(handle);
      this->close();
      return 3;
   }

   errmsg = "";
   return 0;
}

void PcapReader::close()
{
   if (handle != NULL) {
      pcap_close(handle);
      handle = NULL;
   }
}

int PcapReader::get_pkt(Packet &packet)
{
   if (handle == NULL) {
      errmsg = "No live capture or file opened.";
      return -3;
   }

   int ret = pcap_dispatch(handle, 1, packet_handler, (u_char *)(&packet));
   if (ret < 0) {
      errmsg = pcap_geterr(handle);
   }

   return ret;
}
