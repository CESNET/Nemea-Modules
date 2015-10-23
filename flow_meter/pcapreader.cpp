/**
 * \file pcapreader.cpp
 */

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

/**
 * \brief Swap an IPv6 address bytes.
 */
inline void swapbytes128(char *x)
{
   char tmp;
   for (int i = 0; i < 8; i++) {
      tmp = x[i];
      x[i] = x[15 - i];
      x[15 - i] = tmp;
   }
}

#ifdef DEBUG
static uint32_t s_total_pkts = 0;
#endif /* DEBUG */

/**
 * \brief Serves to distinguish between valid (parsed) and non-valid packet.
 */
bool packet_valid = false;

/**
 * \brief Parsing callback function for pcap_dispatch() call. Parse packets up to tranport layer.
 * \param [in,out] arg Serves for passing pointer into callback function.
 * \param [in] h Contains timestamp and packet size.
 * \param [in] data Pointer to the captured packet data.
 */
void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data)
{
   Packet &pkt = *(Packet *)arg;
   const u_char *data_ptr = data;
   struct ethhdr *eth = (struct ethhdr *)data_ptr;
   uint8_t transport_proto = 0;
   uint16_t payload_len = 0;
#ifdef DEBUG
   printf("---------- packet parser  #%u -------------\n", ++s_total_pkts);
   printf("Time:\t\t\t%ld.%ld\n",      h->ts.tv_sec, h->ts.tv_usec);
   printf("Packet length:\t\tcaplen=%uB len=%uB\n\n", h->caplen, h->len);

   printf("Ethernet header:\n");
   printf("\tDest mac:\t%s\n",         ether_ntoa((struct ether_addr *)eth->h_dest));
   printf("\tSrc mac:\t%s\n",          ether_ntoa((struct ether_addr *)eth->h_source));
#endif /* DEBUG */

   uint16_t ethertype = ntohs(eth->h_proto);
#ifdef DEBUG
   printf("\tEthertype:\t%#06x\n",     ethertype);
#endif /* DEBUG */

   if (ethertype == ETH_P_8021Q) {
#ifdef DEBUG
      uint16_t vlan = ntohs(*(unsigned uint32_t *)(data_ptr + 14));
      printf("\t802.1Q field:\n");
      printf("\t\tPriority:\t%u\n",    ((vlan & 0xE000) >> 12));
      printf("\t\tCFI:\t\t%u\n",       ((vlan & 0x1000) >> 11));
      printf("\t\tVLAN:\t\t%u\n",      (vlan & 0x0FFF));
#endif /* DEBUG */
      data_ptr += 18;
      ethertype = ntohs(*(uint16_t *)&data_ptr[-2]);
#ifdef DEBUG
      printf("\t\tEthertype:\t%#06x\n",     ethertype);
#endif /* DEBUG */
   } else {
      data_ptr += 14;
   }

   pkt.packetFieldIndicator = PCKT_TIMESTAMP;
   pkt.timestamp = h->ts.tv_sec + h->ts.tv_usec / 1000000.0;

   if (ethertype == ETH_P_IP) {
      struct iphdr *ip = (struct iphdr *)(data_ptr);

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
      data_ptr += ip->ihl * 4;

#ifdef DEBUG
      printf("IPv4 header:\n");
      printf("\tHDR version:\t%u\n",   ip->version);
      printf("\tHDR length:\t%u\n",    ip->ihl);
      printf("\tTOS:\t\t%u\n",         ip->tos);
      printf("\tTotal length:\t%u\n",  ntohs(ip->tot_len));
      printf("\tID:\t\t%#x\n",         ntohs(ip->id));
      printf("\tFlags:\t\t%#x\n",      ((ntohs(ip->frag_off) & 0xE000) >> 13));
      printf("\tFrag off:\t%#x\n",     (ntohs(ip->frag_off) & 0x1FFF));
      printf("\tTTL:\t\t%u\n",         ip->ttl);
      printf("\tProtocol:\t%u\n",      ip->protocol);
      printf("\tChecksum:\t%#06x\n",   ntohs(ip->check));
      printf("\tSrc addr:\t%s\n",      inet_ntoa(*(struct in_addr *)(&ip->saddr)));
      printf("\tDest addr:\t%s\n",     inet_ntoa(*(struct in_addr *)(&ip->daddr)));
#endif /* DEBUG */

   } else if (ethertype == ETH_P_IPV6) {
      struct ip6_hdr *ip6 = (struct ip6_hdr *)(data_ptr);

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
      data_ptr += 40;

#ifdef DEBUG
      char buffer[INET6_ADDRSTRLEN];
      printf("IPv6 header:\n");
      printf("\tVersion:\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28);
      printf("\tClass:\t\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20);
      printf("\tFlow:\t\t%#x\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff));
      printf("\tLength:\t\t%u\n",      ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
      printf("\tProtocol:\t%u\n",      ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
      printf("\tHop limit:\t%u\n",     ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

      inet_ntop(AF_INET6, (const void *)&ip6->ip6_src, buffer, INET6_ADDRSTRLEN);
      printf("\tSrc addr:\t%s\n",      buffer);
      inet_ntop(AF_INET6, (const void *)&ip6->ip6_dst, buffer, INET6_ADDRSTRLEN);
      printf("\tDest addr:\t%s\n",     buffer);
#endif /* DEBUG */
   } else {
#ifdef DEBUG
      printf("Packet parser exits: unknown ethernet type: %#06x\n", ethertype);
#endif /* DEBUG */
      return;
   }

   if (transport_proto == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(data_ptr);

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

      data_ptr += tcp->doff * 4;
      payload_len -= tcp->doff * 4;

#ifdef DEBUG
      printf("TCP header:\n");
      printf("\tSrc port:\t%u\n",   ntohs(tcp->source));
      printf("\tDest port:\t%u\n",  ntohs(tcp->dest));
      printf("\tSEQ:\t\t%#x\n",     ntohl(tcp->seq));
      printf("\tACK SEQ:\t%#x\n",   ntohl(tcp->ack_seq));
      printf("\tData offset:\t%u\n",tcp->doff);
      printf("\tFlags:\t\t%s%s%s%s%s%s\n", (tcp->fin ? "FIN " : ""), (tcp->syn ? "SYN " : ""), (tcp->rst ? "RST " : ""), (tcp->psh ? "PSH " : ""), (tcp->ack ? "ACK " : ""), (tcp->urg ? "URG" : ""));
      printf("\tWindow:\t\t%u\n",   ntohs(tcp->window));
      printf("\tChecksum:\t%#06x\n",ntohs(tcp->check));
      printf("\tUrg ptr:\t%#x\n",   ntohs(tcp->urg_ptr));
      printf("\tReserved1:\t%#x\n", tcp->res1);
      printf("\tReserved2:\t%#x\n", tcp->res2);
#endif /* DEBUG */

   } else if (transport_proto == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)(data_ptr);

      pkt.sourceTransportPort = ntohs(udp->source);
      pkt.destinationTransportPort = ntohs(udp->dest);
      pkt.packetFieldIndicator |= PCKT_UDP_MASK;

      data_ptr += 8;
      payload_len -= 8;

#ifdef DEBUG
      printf("UDP header:\n");
      printf("\tSrc port:\t%u\n",   ntohs(udp->source));
      printf("\tDest port:\t%u\n",  ntohs(udp->dest));
      printf("\tLength:\t\t%u\n",   ntohs(udp->len));
      printf("\tChecksum:\t%#06x\n",ntohs(udp->check));
#endif /* DEBUG */

   } else if (transport_proto == IPPROTO_ICMP) {
#ifdef DEBUG
      struct icmphdr *icmp = (struct icmphdr *)(data_ptr);
      printf("ICMP header:\n");
      printf("\tType:\t\t%u\n",     icmp->type);
      printf("\tCode:\t\t%u\n",     icmp->code);
      printf("\tChecksum:\t%#06x\n",ntohs(icmp->checksum));
      printf("\tRest:\t\t%#06x\n",  ntohl(*(uint32_t *)&icmp->un));
#endif /* DEBUG */

   } else if (transport_proto == IPPROTO_ICMPV6) {
#ifdef DEBUG
      struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(data_ptr);
      printf("ICMPv6 header:\n");
      printf("\tType:\t\t%u\n",     icmp6->icmp6_type);
      printf("\tCode:\t\t%u\n",     icmp6->icmp6_code);
      printf("\tChecksum:\t%#x\n",  ntohs(icmp6->icmp6_cksum));
      printf("\tBody:\t\t%#x\n",    ntohs(*(uint32_t *)&icmp6->icmp6_dataun));
#endif /* DEBUG */
   } else {
#ifdef DEBUG
      printf("Packet parser exits: unknown transport protocol: %#06x\n", transport_proto);
#endif /* DEBUG */
      return;
   }

   int len = (data_ptr - data) + payload_len;
   if (len > MAXPCKTSIZE) {
      len = MAXPCKTSIZE;
#ifdef DEBUG
      printf("Packet size too long, truncating to %u.", len);
#endif /* DEBUG */
   }
   memcpy(pkt.packet, data, len);
   pkt.packet[len] = 0;
   pkt.packetTotalLength = len;

   pkt.transportPayloadPacketSectionSize = len - (data_ptr - data);
   pkt.transportPayloadPacketSection = pkt.packet + (data_ptr - data);

   if ((pkt.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK ||
       (pkt.packetFieldIndicator & PCKT_UDP_MASK) == PCKT_UDP_MASK) {
      pkt.packetFieldIndicator |= PCKT_PAYLOAD_MASK;
   }

#ifdef DEBUG
   printf("Payload length:\t%u\n", payload_len);
   printf("Packet parser exits: packet parsed\n");
#endif /* DEBUG */
   packet_valid = true;
}

/**
 * \brief Constructor.
 */
PcapReader::PcapReader() : handle(NULL)
{
}

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
PcapReader::PcapReader(const options_t &options) : handle(NULL)
{
}

/**
 * \brief Destructor.
 */
PcapReader::~PcapReader()
{
   this->close();
}

/**
 * \brief Open pcap file for reading.
 * \param [in] file Input file name.
 * \return 0 on success, non 0 on failure + errmsg is filled with error message
 */
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

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \return 0 on success, non 0 on failure + errmsg is filled with error message
 */
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

/**
 * \brief Close opened file or interface.
 */
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

   packet_valid = false;
   int ret = pcap_dispatch(handle, 1, packet_handler, (u_char *)(&packet));

   if (ret == 1 && packet_valid) {
      return 2;
   }
   if (ret < 0) {
      errmsg = pcap_geterr(handle);
   }
   return ret;
}
