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

//#define DEBUG
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

#ifdef DEBUG
static uint32_t s_total_pkts = 0;
#endif /* DEBUG */

void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data)
{
   Packet &pkt = *(Packet *)arg;
   struct ethhdr *eth = (struct ethhdr *)data;
   uint8_t transport_proto = 0;
   uint16_t payload_len = 0;
#ifdef DEBUG
   printf("---------- packet parser  #%u -------------\n", ++s_total_pkts);
   printf("Time:\t\t\t%ld.%ld\n",      h->ts.tv_sec, h->ts.tv_usec);
   printf("Packet length:\t\tcaplen=%uB len=%uB\n\n", h->caplen, h->len);

   printf("Ethernet header:\n");
   printf("\tDEST MAC:\t%s\n",         ether_ntoa((struct ether_addr *)eth->h_dest));
   printf("\tSOURCE MAC:\t%s\n",       ether_ntoa((struct ether_addr *)eth->h_source));
#endif /* DEBUG */

   uint16_t ethertype = ntohs(eth->h_proto);
   if (ethertype == ETH_P_8021Q) {
#ifdef DEBUG
      printf("\t802.1Q field:\t%#06x\n", *(unsigned uint32_t*)(data + 12));
#endif /* DEBUG */
      data += 18;
      ethertype = ntohs(data[-2]);
   } else {
      data += 14;
   }

#ifdef DEBUG
   printf("\tETHERTYPE:\t%#06x\n",     ntohs(eth->h_proto));
#endif /* DEBUG */

   pkt.packetFieldIndicator = PCKT_TIMESTAMP;
   pkt.timestamp = h->ts.tv_sec + h->ts.tv_usec/1000000.0;

   if (ethertype == ETH_P_IP) {
      struct iphdr *ip = (struct iphdr *)(data);

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

#ifdef DEBUG
      printf("IPv4:\n");
      printf("\tHDR VERSION:\t%u\n",   ip->version);
      printf("\tHDR LENGTH:\t%u\n",    ip->ihl);
      printf("\tTOS:\t\t%u\n",         ip->tos);
      printf("\tTOTAL LENGTH:\t%u\n",  ntohs(ip->tot_len));
      printf("\tID:\t\t%u\n",          ip->id);
      printf("\tFLAGS:\t\t%#x\n",      ip->frag_off);
      printf("\tTTL:\t\t%u\n",         ip->ttl);
      printf("\tPROTO:\t\t%u\n",       ip->protocol);
      printf("\tCHECK:\t\t%#06x\n",    ntohs(ip->check));
      printf("\tSOURCE ADDR:\t%s\n",   inet_ntoa(*(struct in_addr *)(&ip->saddr)));
      printf("\tDEST ADDR:\t%s\n",     inet_ntoa(*(struct in_addr *)(&ip->daddr)));
#endif /* DEBUG */

   } else if (ethertype == ETH_P_IPV6) {
      struct ip6_hdr *ip6 = (struct ip6_hdr *)(data);

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

#ifdef DEBUG
      char buffer[INET6_ADDRSTRLEN];
      printf("IPv6:\n");
      printf("\tVERSION:\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28);
      printf("\tCLASS:\t\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20);
      printf("\tFLOW:\t\t%#x\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff));
      printf("\tLENGTH:\t\t%u\n",      ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
      printf("\tPROTO:\t\t%u\n",       ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
      printf("\tHOP LIMIT:\t%u\n",     ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

      inet_ntop(AF_INET6, (const void *)&ip6->ip6_src, buffer, INET6_ADDRSTRLEN);
      printf("\tSOURCE ADDR:\t%s\n",   buffer);
      inet_ntop(AF_INET6, (const void *)&ip6->ip6_dst, buffer, INET6_ADDRSTRLEN);
      printf("\tDEST ADDR:\t%s\n",     buffer);
#endif /* DEBUG */
   } else {
#ifdef DEBUG
      printf("Packet parser exits: unknown ethernet type: %#06X\n", ethertype);
#endif /* DEBUG */
      return;
   }

   if (transport_proto == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(data);

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

#ifdef DEBUG
      printf("TCP:\n");
      printf("\tSOURCE PORT:\t%u\n",ntohs(tcp->source));
      printf("\tDEST PORT:\t%u\n",  ntohs(tcp->dest));
      printf("\tSEQ:\t\t%#x\n",     ntohl(tcp->seq));
      printf("\tACK SEQ:\t%#x\n",   ntohl(tcp->ack_seq));
      printf("\tDATA OFFSET:\t%u\n",tcp->doff);
      printf("\tFLAGS:\t\t%s%s%s%s%s%s\n",      (tcp->fin?"FIN ":""), (tcp->syn?"SYN ":""), (tcp->rst?"RST ":""), (tcp->psh?"PSH ":""), (tcp->ack?"ACK ":""), (tcp->urg?"URG":""));
      printf("\tWINDOW:\t\t%u\n",   ntohs(tcp->window));
      printf("\tCHECK:\t\t%#06x\n", ntohs(tcp->check));
      printf("\tURG PTR:\t%#x\n",   ntohs(tcp->urg_ptr));
      printf("\tRES1:\t\t%#x\n",    tcp->res1);
      printf("\tRES2:\t\t%#x\n",    tcp->res2);
#endif /* DEBUG */
   } else if (transport_proto == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)(data);

      pkt.sourceTransportPort = ntohs(udp->source);
      pkt.destinationTransportPort = ntohs(udp->dest);
      pkt.packetFieldIndicator |= PCKT_UDP_MASK;

      data += 8;
      payload_len -= 8;

#ifdef DEBUG
      printf("UDP:\n");
      printf("\tSOURCE PORT:\t%u\n",ntohs(udp->source));
      printf("\tDEST PORT:\t%u\n",  ntohs(udp->dest));
      printf("\tLENGTH:\t\t%u\n",   ntohs(udp->len));
      printf("\tCHECK:\t\t%#06x\n", ntohs(udp->check));
#endif /* DEBUG */
   } else if (transport_proto == IPPROTO_ICMP) {
#ifdef DEBUG
      struct icmphdr *icmp = (struct icmphdr *)(data);
      printf("ICMP:\n");
      printf("\tTYPE:\t\t%u\n",     icmp->type);
      printf("\tCODE:\t\t%u\n",     icmp->code);
      printf("\tCHECKSUM:\t%#06x\n",ntohs(icmp->checksum));
      printf("\tREST:\t\t%#06x\n",  ntohl(*(uint32_t *)&icmp->un));
#endif /* DEBUG */
   } else if (transport_proto == IPPROTO_ICMPV6) {
#ifdef DEBUG
      struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(data);
      printf("ICMPv6:\n");
      printf("\tTYPE:\t\t%u\n",     icmp6->icmp6_type);
      printf("\tCODE:\t\t%u\n",     icmp6->icmp6_code);
      printf("\tCHECKSUM:\t%#x\n",  ntohs(icmp6->icmp6_cksum));
      printf("\tBODY:\t\t%#x\n",    ntohs(*(uint32_t *)&icmp6->icmp6_dataun));
#endif /* DEBUG */
   } else {
#ifdef DEBUG
      printf("Packet parser exits: unknown transport protocol: %#06X\n", transport_proto);
#endif /* DEBUG */
      return;
   }

   if (((pkt.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) ||
       ((pkt.packetFieldIndicator & PCKT_UDP_MASK) == PCKT_UDP_MASK)) {
      if (payload_len <= MAXPCKTPAYLOADSIZE) {
         pkt.transportPayloadPacketSectionSize = payload_len;
         memcpy(pkt.transportPayloadPacketSection, data, payload_len);
         pkt.transportPayloadPacketSection[payload_len] = 0;
         pkt.packetFieldIndicator |= PCKT_PAYLOAD_MASK;
      }

#ifdef DEBUG
      printf("PAYLOAD LENGTH:\t%u\n", payload_len);
#endif /* DEBUG */
   }

   pkt.packetFieldIndicator |= PCKT_VALID;
#ifdef DEBUG
   printf("Packet parser exits: packet parsed\n");
#endif /* DEBUG */
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
   errbuf[0] = 0;

   handle = pcap_open_live(interface.c_str(), 1 << 15, 1, 0, errbuf);
   if (handle == NULL) {
      errmsg = errbuf;
      return 2;
   }
   if (errbuf[0] != 0) {
      fprintf(stderr, "%s\n", errbuf); // Print warning.
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
