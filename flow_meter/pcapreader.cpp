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

#include <cstdio>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <pcap/pcap.h>

#include "pcapreader.h"

using namespace std;

// Read timeout in miliseconds for pcap_open_live function.
#define READ_TIMEOUT 1000

// Interval between pcap handle stats print in seconds.
#define STATS_PRINT_INTERVAL  5

//#define DEBUG_PARSER

#ifdef DEBUG_PARSER
// Print debug message if debugging is allowed.
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
// Process code if debugging is allowed.
#define DEBUG_CODE(code) code
#else
#define DEBUG_MSG(format, ...)
#define DEBUG_CODE(code)
#endif

#ifdef DEBUG_PARSER
static uint32_t s_total_pkts = 0;
#endif /* DEBUG_PARSER */

/**
 * \brief Distinguish between valid (parsed) and non-valid packet.
 */
bool packet_valid = false;

/**
 * \brief Parse specific fields from ETHERNET frame header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_eth_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct ethhdr *eth = (struct ethhdr *) data_ptr;
   uint16_t hdr_len, ethertype = ntohs(eth->h_proto);

   DEBUG_MSG("Ethernet header:\n");
   DEBUG_MSG("\tDest mac:\t%s\n",         ether_ntoa((struct ether_addr *) eth->h_dest));
   DEBUG_MSG("\tSrc mac:\t%s\n",          ether_ntoa((struct ether_addr *) eth->h_source));
   DEBUG_MSG("\tEthertype:\t%#06x\n",     ethertype);

   if (ethertype == ETH_P_8021Q) {
      DEBUG_CODE(uint16_t vlan = ntohs(*(unsigned uint32_t *) (data_ptr + 14)));
      DEBUG_MSG("\t802.1Q field:\n");
      DEBUG_MSG("\t\tPriority:\t%u\n",    ((vlan & 0xE000) >> 12));
      DEBUG_MSG("\t\tCFI:\t\t%u\n",       ((vlan & 0x1000) >> 11));
      DEBUG_MSG("\t\tVLAN:\t\t%u\n",      (vlan & 0x0FFF));

      hdr_len = 18;
      ethertype = ntohs(*(uint16_t *) &data_ptr[16]);
      DEBUG_MSG("\t\tEthertype:\t%#06x\n", ethertype);
   } else {
      hdr_len = 14;
   }

   pkt->ethertype = ethertype;

   return hdr_len;
}

/**
 * \brief Parse specific fields from IPv4 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_ipv4_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct iphdr *ip = (struct iphdr *) data_ptr;

   pkt->field_indicator |= PCKT_IPV4_MASK;
   pkt->ip_version = ip->version;
   pkt->ip_proto = ip->protocol;
   pkt->ip_tos = ip->tos;
   pkt->ip_length = ntohs(ip->tot_len);
   pkt->ip_ttl = ip->ttl;
   pkt->src_ip.v4 = ip->saddr;
   pkt->dst_ip.v4 = ip->daddr;

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
   DEBUG_MSG("\tSrc addr:\t%s\n",      inet_ntoa(*(struct in_addr *) (&ip->saddr)));
   DEBUG_MSG("\tDest addr:\t%s\n",     inet_ntoa(*(struct in_addr *) (&ip->daddr)));

   return (ip->ihl << 2);
}
/**
 * \brief Parse specific fields from IPv6 header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_ipv6_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct ip6_hdr *ip6 = (struct ip6_hdr *) data_ptr;
   uint16_t hdr_len = 40;

   pkt->field_indicator |= PCKT_IPV6_MASK;
   pkt->ip_version = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28;
   pkt->ip_tos = (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20;
   pkt->ip_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
   pkt->ip_length = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
   memcpy(pkt->src_ip.v6, (const char *) &ip6->ip6_src, 16);
   memcpy(pkt->dst_ip.v6, (const char *) &ip6->ip6_dst, 16);

   DEBUG_CODE(char buffer[INET6_ADDRSTRLEN]);
   DEBUG_MSG("IPv6 header:\n");
   DEBUG_MSG("\tVersion:\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xf0000000) >> 28);
   DEBUG_MSG("\tClass:\t\t%u\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0ff00000) >> 20);
   DEBUG_MSG("\tFlow:\t\t%#x\n",       (ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff));
   DEBUG_MSG("\tLength:\t\t%u\n",      ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
   DEBUG_MSG("\tProtocol:\t%u\n",      ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
   DEBUG_MSG("\tHop limit:\t%u\n",     ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);

   DEBUG_CODE(inet_ntop(AF_INET6, (const void *) &ip6->ip6_src, buffer, INET6_ADDRSTRLEN));
   DEBUG_MSG("\tSrc addr:\t%s\n",      buffer);
   DEBUG_CODE(inet_ntop(AF_INET6, (const void *) &ip6->ip6_dst, buffer, INET6_ADDRSTRLEN));
   DEBUG_MSG("\tDest addr:\t%s\n",     buffer);

   return hdr_len;
}

/**
 * \brief Parse specific fields from TCP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_tcp_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct tcphdr *tcp = (struct tcphdr *) data_ptr;

   pkt->field_indicator |= PCKT_PAYLOAD_MASK;
   pkt->field_indicator |= PCKT_TCP_MASK;
   pkt->src_port = ntohs(tcp->source);
   pkt->dst_port = ntohs(tcp->dest);
   pkt->tcp_control_bits = (uint8_t) *(data_ptr + 13) & 0x3F;

   DEBUG_MSG("TCP header:\n");
   DEBUG_MSG("\tSrc port:\t%u\n",   ntohs(tcp->source));
   DEBUG_MSG("\tDest port:\t%u\n",  ntohs(tcp->dest));
   DEBUG_MSG("\tSEQ:\t\t%#x\n",     ntohl(tcp->seq));
   DEBUG_MSG("\tACK SEQ:\t%#x\n",   ntohl(tcp->ack_seq));
   DEBUG_MSG("\tData offset:\t%u\n",tcp->doff);
   DEBUG_MSG("\tFlags:\t\t%s%s%s%s%s%s\n", (tcp->fin ? "FIN " : ""), (tcp->syn ? "SYN " : ""),
                                           (tcp->rst ? "RST " : ""), (tcp->psh ? "PSH " : ""),
                                           (tcp->ack ? "ACK " : ""), (tcp->urg ? "URG"  : ""));
   DEBUG_MSG("\tWindow:\t\t%u\n",   ntohs(tcp->window));
   DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(tcp->check));
   DEBUG_MSG("\tUrg ptr:\t%#x\n",   ntohs(tcp->urg_ptr));
   DEBUG_MSG("\tReserved1:\t%#x\n", tcp->res1);
   DEBUG_MSG("\tReserved2:\t%#x\n", tcp->res2);

   return (tcp->doff << 2);
}

/**
 * \brief Parse specific fields from UDP header.
 * \param [in] data_ptr Pointer to begin of header.
 * \param [out] pkt Pointer to Packet structure where parsed fields will be stored.
 * \return Size of header in bytes.
 */
inline uint16_t parse_udp_hdr(const u_char *data_ptr, Packet *pkt)
{
   struct udphdr *udp = (struct udphdr *) data_ptr;

   pkt->field_indicator |= PCKT_PAYLOAD_MASK;
   pkt->field_indicator |= PCKT_UDP_MASK;
   pkt->src_port = ntohs(udp->source);
   pkt->dst_port = ntohs(udp->dest);

   DEBUG_MSG("UDP header:\n");
   DEBUG_MSG("\tSrc port:\t%u\n",   ntohs(udp->source));
   DEBUG_MSG("\tDest port:\t%u\n",  ntohs(udp->dest));
   DEBUG_MSG("\tLength:\t\t%u\n",   ntohs(udp->len));
   DEBUG_MSG("\tChecksum:\t%#06x\n",ntohs(udp->check));

   return 8;
}

/**
 * \brief Parsing callback function for pcap_dispatch() call. Parse packets up to transport layer.
 * \param [in,out] arg Serves for passing pointer to Packet structure into callback function.
 * \param [in] h Contains timestamp and packet size.
 * \param [in] data Pointer to the captured packet data.
 */
void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data)
{
   Packet *pkt = (Packet *) arg;
   uint16_t data_offset = 0;

   DEBUG_MSG("---------- packet parser  #%u -------------\n", ++s_total_pkts);
   DEBUG_CODE(
      char timestamp[32];
      time_t time = h->ts.tv_sec;
      strftime(timestamp, sizeof(timestamp), "%FT%T", localtime(&time));
   );
   DEBUG_MSG("Time:\t\t\t%s.%06lu\n",     timestamp, h->ts.tv_usec);
   DEBUG_MSG("Packet length:\t\tcaplen=%uB len=%uB\n\n", h->caplen, h->len);

   pkt->field_indicator = PCKT_PCAP_MASK;
   pkt->timestamp = h->ts;
   pkt->src_port = 0;
   pkt->dst_port = 0;
   pkt->ip_proto = 0;

   data_offset = parse_eth_hdr(data, pkt);
   if (pkt->ethertype == ETH_P_IP) {
      data_offset += parse_ipv4_hdr(data + data_offset, pkt);
   } else if (pkt->ethertype == ETH_P_IPV6) {
      data_offset += parse_ipv6_hdr(data + data_offset, pkt);
   }

   if (pkt->ip_proto == IPPROTO_TCP) {
      data_offset += parse_tcp_hdr(data + data_offset, pkt);
   } else if (pkt->ip_proto == IPPROTO_UDP) {
      data_offset += parse_udp_hdr(data + data_offset, pkt);
   }

   uint32_t len = h->caplen;
   if (len > MAXPCKTSIZE) {
      len = MAXPCKTSIZE;
      DEBUG_MSG("Packet size too long, truncating to %u\n", len);
   }
   memcpy(pkt->packet, data, len);
   pkt->packet[len] = 0;
   pkt->total_length = len;

   pkt->payload_length = len - data_offset;
   pkt->payload = pkt->packet + data_offset;

   DEBUG_MSG("Payload length:\t%u\n", pkt->payload_length);
   DEBUG_MSG("Packet parser exits: packet parsed\n");
   packet_valid = true;
}

/**
 * \brief Constructor.
 */
PcapReader::PcapReader() : handle(NULL), print_pcap_stats(false)
{
}

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
PcapReader::PcapReader(const options_t &options) : handle(NULL)
{
   print_pcap_stats = options.print_pcap_stats;
   last_ts.tv_sec = 0;
   last_ts.tv_usec = 0;
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
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int PcapReader::open_file(const string &file)
{
   if (handle != NULL) {
      error_msg = "Interface or pcap file is already opened.";
      return 1;
   }

   char error_buffer[PCAP_ERRBUF_SIZE];
   handle = pcap_open_offline(file.c_str(), error_buffer);
   if (handle == NULL) {
      error_msg = error_buffer;
      return 2;
   }

   if (print_pcap_stats) {
      printf("PcapReader: warning: printing pcap stats is only supported in live capture\n");
   }

   live_capture = false;
   error_msg = "";
   return 0;
}

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int PcapReader::init_interface(const string &interface)
{
   if (handle != NULL) {
      error_msg = "Interface or pcap file is already opened.";
      return 1;
   }

   char errbuf[PCAP_ERRBUF_SIZE];
   errbuf[0] = 0;

   handle = pcap_open_live(interface.c_str(), MAXPCKTSIZE, 1, READ_TIMEOUT, errbuf);
   if (handle == NULL) {
      error_msg = errbuf;
      return 2;
   }
   if (errbuf[0] != 0) {
      fprintf(stderr, "%s\n", errbuf); // Print warning.
   }

   if (print_pcap_stats) {
      /* Print stats header. */
      printf("# recv   - number of packets received\n");
      printf("# drop   - number  of  packets dropped because there was no room in the operating system's buffer when they arrived, because packets weren't being read fast enough\n");
      printf("# ifdrop - number of packets dropped by the network interface or its driver\n\n");
      printf("recv\tdrop\tifdrop\n");
   }

   live_capture = true;
   error_msg = "";
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

void PcapReader::print_stats()
{
   /* Only live capture stats are supported. */
   if (live_capture) {
      struct timeval tmp;

      gettimeofday(&tmp, NULL);
      if (tmp.tv_sec - last_ts.tv_sec >= STATS_PRINT_INTERVAL) {
         struct pcap_stat stats;
         if (pcap_stats(handle, &stats) == -1) {
            printf("PcapReader: error: %s\n", pcap_geterr(handle));
            print_pcap_stats = false; /* Turn off printing stats. */
            return;
         }
         printf("%d\t%d\t%d\n", stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);

         last_ts = tmp;
      }
   }
}

int PcapReader::get_pkt(Packet &packet)
{
   if (handle == NULL) {
      error_msg = "No live capture or file opened.";
      return -3;
   }

   int ret;
   packet_valid = false;

   if (print_pcap_stats) {
      print_stats();
   }

   // Get pkt from network interface or file.
   ret = pcap_dispatch(handle, 1, packet_handler, (u_char *) (&packet));
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
      error_msg = pcap_geterr(handle);
   }
   return ret;
}
