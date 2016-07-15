/**
 * \file pcapreader.cpp
 * \brief Pcap reader based on libpcap
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

//#define DEBUG

// Print debug message if debugging is allowed.
#ifdef DEBUG
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

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

   DEBUG_MSG("---------- packet parser  #%u -------------\n", ++s_total_pkts);
   DEBUG_MSG("Time:\t\t\t%ld.%ld\n",      h->ts.tv_sec, h->ts.tv_usec);
   DEBUG_MSG("Packet length:\t\tcaplen=%uB len=%uB\n\n", h->caplen, h->len);

   DEBUG_MSG("Ethernet header:\n");
   DEBUG_MSG("\tDest mac:\t%s\n",         ether_ntoa((struct ether_addr *)eth->h_dest));
   DEBUG_MSG("\tSrc mac:\t%s\n",          ether_ntoa((struct ether_addr *)eth->h_source));

   uint16_t ethertype = ntohs(eth->h_proto);

   DEBUG_MSG("\tEthertype:\t%#06x\n",     ethertype);

   if (ethertype == ETH_P_8021Q) {
      DEBUG_CODE(uint16_t vlan = ntohs(*(unsigned uint32_t *)(data_ptr + 14)));
      DEBUG_MSG("\t802.1Q field:\n");
      DEBUG_MSG("\t\tPriority:\t%u\n",    ((vlan & 0xE000) >> 12));
      DEBUG_MSG("\t\tCFI:\t\t%u\n",       ((vlan & 0x1000) >> 11));
      DEBUG_MSG("\t\tVLAN:\t\t%u\n",      (vlan & 0x0FFF));

      data_ptr += 18;
      ethertype = ntohs(*(uint16_t *)&data_ptr[-2]);
      DEBUG_MSG("\t\tEthertype:\t%#06x\n",     ethertype);
   } else {
      data_ptr += 14;
   }

   pkt.packetFieldIndicator = PCKT_TIMESTAMP;
   pkt.timestamp = h->ts.tv_sec + h->ts.tv_usec / 1000000.0;

   if (ethertype == ETH_P_IP) {
      struct iphdr *ip = (struct iphdr *)data_ptr;

      pkt.ipVersion = ip->version;
      pkt.protocolIdentifier = ip->protocol;
      pkt.ipClassOfService = ip->tos;
      pkt.ipLength = ntohs(ip->tot_len);
      pkt.ipTtl = ip->ttl;
      pkt.sourceIPv4Address = ip->saddr;
      pkt.destinationIPv4Address = ip->daddr;
      pkt.packetFieldIndicator |= PCKT_IPV4_MASK;

      transport_proto = ip->protocol;
      payload_len = ntohs(ip->tot_len) - ip->ihl * 4;
      data_ptr += ip->ihl * 4;

      DEBUG_MSG("IPv4 header:\n");
      DEBUG_MSG("\tHDR version:\t%u\n",   ip->version);
      DEBUG_MSG("\tHDR length:\t%u\n",    ip->ihl);
      DEBUG_MSG("\tTOS:\t\t%u\n",         ip->tos);
      DEBUG_MSG("\tTotal length:\t%u\n",  ntohs(ip->tot_len));
      DEBUG_MSG("\tID:\t\t%#x\n",         ntohs(ip->id));
      DEBUG_MSG("\tFlags:\t\t%#x\n",      ((ntohs(ip->frag_off) & 0xE000) >> 13));
      DEBUG_MSG("\tFrag off:\t%#x\n",     (ntohs(ip->frag_off) & 0x1FFF));
      DEBUG_MSG("\tTTL:\t\t%u\n",         ip->ttl);
      DEBUG_MSG("\tProtocol:\t%u\n",      ip->protocol);
      DEBUG_MSG("\tChecksum:\t%#06x\n",   ntohs(ip->check));
      DEBUG_MSG("\tSrc addr:\t%s\n",      inet_ntoa(*(struct in_addr *)(&ip->saddr)));
      DEBUG_MSG("\tDest addr:\t%s\n",     inet_ntoa(*(struct in_addr *)(&ip->daddr)));

   } else if (ethertype == ETH_P_IPV6) {
      struct ip6_hdr *ip6 = (struct ip6_hdr *)data_ptr;

      pkt.ipVersion = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28;
      pkt.ipClassOfService = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20;
      pkt.protocolIdentifier = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      pkt.ipLength = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
      memcpy(pkt.sourceIPv6Address, (const char *)&ip6->ip6_src, 16);
      memcpy(pkt.destinationIPv6Address, (const char *)&ip6->ip6_dst, 16);
      pkt.packetFieldIndicator |= PCKT_IPV6_MASK;

      transport_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      payload_len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);   //TODO: IPv6 Extension header
      data_ptr += 40;

      DEBUG_CODE(char buffer[INET6_ADDRSTRLEN]);
      DEBUG_MSG("IPv6 header:\n");
      DEBUG_MSG("\tVersion:\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28);
      DEBUG_MSG("\tClass:\t\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20);
      DEBUG_MSG("\tFlow:\t\t%#x\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff));
      DEBUG_MSG("\tLength:\t\t%u\n",      ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
      DEBUG_MSG("\tProtocol:\t%u\n",      ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
      DEBUG_MSG("\tHop limit:\t%u\n",     ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

      DEBUG_CODE(inet_ntop(AF_INET6, (const void *)&ip6->ip6_src, buffer, INET6_ADDRSTRLEN));
      DEBUG_MSG("\tSrc addr:\t%s\n",      buffer);
      DEBUG_CODE(inet_ntop(AF_INET6, (const void *)&ip6->ip6_dst, buffer, INET6_ADDRSTRLEN));
      DEBUG_MSG("\tDest addr:\t%s\n",     buffer);
   } else {
      DEBUG_MSG("Packet parser exits: unknown ethernet type: %#06x\n", ethertype);
      return;
   }

   if (transport_proto == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)data_ptr;

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

      DEBUG_MSG("TCP header:\n");
      DEBUG_MSG("\tSrc port:\t%u\n",   ntohs(tcp->source));
      DEBUG_MSG("\tDest port:\t%u\n",  ntohs(tcp->dest));
      DEBUG_MSG("\tSEQ:\t\t%#x\n",     ntohl(tcp->seq));
      DEBUG_MSG("\tACK SEQ:\t%#x\n",   ntohl(tcp->ack_seq));
      DEBUG_MSG("\tData offset:\t%u\n",tcp->doff);
      DEBUG_MSG("\tFlags:\t\t%s%s%s%s%s%s\n", (tcp->fin ? "FIN " : ""), (tcp->syn ? "SYN " : ""), (tcp->rst ? "RST " : ""), (tcp->psh ? "PSH " : ""), (tcp->ack ? "ACK " : ""), (tcp->urg ? "URG" : ""));
      DEBUG_MSG("\tWindow:\t\t%u\n",   ntohs(tcp->window));
      DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(tcp->check));
      DEBUG_MSG("\tUrg ptr:\t%#x\n",   ntohs(tcp->urg_ptr));
      DEBUG_MSG("\tReserved1:\t%#x\n", tcp->res1);
      DEBUG_MSG("\tReserved2:\t%#x\n", tcp->res2);
   } else if (transport_proto == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)data_ptr;

      pkt.sourceTransportPort = ntohs(udp->source);
      pkt.destinationTransportPort = ntohs(udp->dest);
      pkt.packetFieldIndicator |= PCKT_UDP_MASK;

      data_ptr += 8;
      payload_len -= 8;

      DEBUG_MSG("UDP header:\n");
      DEBUG_MSG("\tSrc port:\t%u\n",   ntohs(udp->source));
      DEBUG_MSG("\tDest port:\t%u\n",  ntohs(udp->dest));
      DEBUG_MSG("\tLength:\t\t%u\n",   ntohs(udp->len));
      DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(udp->check));
   } else if (transport_proto == IPPROTO_ICMP) {
      DEBUG_CODE(struct icmphdr *icmp = (struct icmphdr *)data_ptr);
      DEBUG_MSG("ICMP header:\n");
      DEBUG_MSG("\tType:\t\t%u\n",     icmp->type);
      DEBUG_MSG("\tCode:\t\t%u\n",     icmp->code);
      DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(icmp->checksum));
      DEBUG_MSG("\tRest:\t\t%#06x\n",  ntohl(*(uint32_t *)&icmp->un));
   } else if (transport_proto == IPPROTO_ICMPV6) {
      DEBUG_CODE(struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)data_ptr);
      DEBUG_MSG("ICMPv6 header:\n");
      DEBUG_MSG("\tType:\t\t%u\n",     icmp6->icmp6_type);
      DEBUG_MSG("\tCode:\t\t%u\n",     icmp6->icmp6_code);
      DEBUG_MSG("\tChecksum:\t%#x\n",  ntohs(icmp6->icmp6_cksum));
      DEBUG_MSG("\tBody:\t\t%#x\n",    ntohs(*(uint32_t *)&icmp6->icmp6_dataun));
   } else {
      DEBUG_MSG("Packet parser exits: unknown transport protocol: %#06x\n", transport_proto);
      return;
   }

   int len = (data_ptr - data) + payload_len;
   if (len > MAXPCKTSIZE) {
      len = MAXPCKTSIZE;
      DEBUG_MSG("Packet size too long, truncating to %u\n", len);
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

   DEBUG_MSG("Payload length:\t%u\n", payload_len);
   DEBUG_MSG("Packet parser exits: packet parsed\n");
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

   live_capture = false;
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

   handle = pcap_open_live(interface.c_str(), 1 << 16, 1, 1000, errbuf);
   if (handle == NULL) {
      errmsg = errbuf;
      return 2;
   }
   if (errbuf[0] != 0) {
      fprintf(stderr, "%s\n", errbuf); // Print warning.
   }

   live_capture = true;
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
   int ret;

   // Get pkt from network interface or file.
   ret = pcap_dispatch(handle, 1, packet_handler, (u_char *)(&packet));
   if (ret == 0) {
      // Read timeout occured or no more packets in file...
      return (live_capture ? 3 : 0);
   }

   if (ret == 1 && packet_valid) {
      // Packet is valid and ready to process by flow_cache.
      return 2;
   }
   if (ret < 0) {
      // Error occured.
      errmsg = pcap_geterr(handle);
   }
   return ret;
}
