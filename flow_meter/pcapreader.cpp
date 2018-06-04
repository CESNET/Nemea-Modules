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
#include "parser.h"

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
 * \brief Parse every packet.
 */
bool parse_all = false;


/**
 * \brief Parsing callback function for pcap_dispatch() call. Parse packets up to transport layer.
 * \param [in,out] arg Serves for passing pointer to Packet structure into callback function.
 * \param [in] h Contains timestamp and packet size.
 * \param [in] data Pointer to the captured packet data.
 */
void packet_handler(u_char *arg, const struct pcap_pkthdr *h, const u_char *data)
{
   Packet *pkt = (Packet *) arg;
   uint32_t pkt_len = h->caplen;
   uint32_t pkt_offset = 0;

   packet_hdr_t *headers = NULL;
   packet_hdr_t *tmp = NULL;

   bool parsed = false;

   pkt->valid = false;
   pkt->timestamp = h->ts;
   pkt->field_indicator = 0;
   pkt->src_port = 0;
   pkt->dst_port = 0;
   pkt->ip_proto = 0;
   pkt->ip_version = 0;
   pkt->tcp_control_bits = 0;

   uint32_t len = pkt_len;
   if (len > MAXPCKTSIZE) {
      len = MAXPCKTSIZE;
   }
   memcpy(pkt->packet, data + (h->caplen - pkt_len), len);
   pkt->packet[len] = 0;
   pkt->total_length = len;

   /* Parse packet using parser generated from P4-16. */
   int ret = fpp_parse_packet(data, pkt_len, &headers);

   switch (ret) {
      case OutOfMemory:
         return;
      case NoError:
      case ParserDefaultReject:
      case NoMatch:
      case StackOutOfBounds:
      case HeaderTooShort:
      case ParserTimeout:
      default:
         break;
   }

   /* Iterate through parsed packet headers linked list. */
   while (headers != NULL) {
      /* Process parsed headers. */
      if (headers->type == fpp_ethernet_h) {
         /* Ethernet */
         struct ethernet_h *eth = (struct ethernet_h *) headers->hdr;

         memcpy(pkt->dst_mac, eth->dst_addr, 6);
         memcpy(pkt->src_mac, eth->src_addr, 6);
         pkt->ethertype = eth->ethertype;
         if (parse_all) {
            pkt->valid = true;
         }
      } else if (headers->type == fpp_ipv4_h) {
         /* IPv4 */
         struct ipv4_h *ip = (struct ipv4_h *) headers->hdr;
         if (parsed) {
            if (pkt->next == NULL) {
               pkt->next = new Packet();
               pkt->next->depth = pkt->depth + 1;
            }
            pkt = pkt->next;
            pkt->valid = true;
            pkt->timestamp = h->ts;
            pkt->field_indicator = 0;
            pkt->src_port = 0;
            pkt->dst_port = 0;
            pkt->tcp_control_bits = 0;
            if (pkt->next != NULL) {
               pkt->next->valid = false;
            }

            pkt_len -= ip->header_offset - pkt_offset;
            pkt_offset = ip->header_offset;

            uint32_t len = pkt_len;
            if (len > MAXPCKTSIZE) {
               len = MAXPCKTSIZE;
            }
            memcpy(pkt->packet, data + (h->caplen - pkt_len), len);
            pkt->packet[len] = 0;
            pkt->total_length = len;
         }

         pkt->ip_version = 4;
         pkt->ip_proto = ip->protocol;
         pkt->ip_tos = ip->diffserv;
         pkt->ip_length = ip->total_len;
         pkt->ip_ttl = ip->ttl;
         pkt->src_ip.v4 = ntohl(ip->src_addr);
         pkt->dst_ip.v4 = ntohl(ip->dst_addr);
         pkt->valid = true;
         parsed = true;
      } else if (headers->type == fpp_ipv6_h) {
         /* IPv6 */
         struct ipv6_h *ip = (struct ipv6_h *) headers->hdr;
         if (parsed) {
            if (pkt->next == NULL) {
               pkt->next = new Packet();
               pkt->next->depth = pkt->depth + 1;
            }
            pkt = pkt->next;
            pkt->valid = true;
            pkt->timestamp = h->ts;
            pkt->field_indicator = 0;
            pkt->src_port = 0;
            pkt->dst_port = 0;
            pkt->tcp_control_bits = 0;
            if (pkt->next != NULL) {
               pkt->next->valid = false;
            }

            pkt_len -= ip->header_offset - pkt_offset;
            pkt_offset = ip->header_offset;

            uint32_t len = pkt_len;
            if (len > MAXPCKTSIZE) {
               len = MAXPCKTSIZE;
            }
            memcpy(pkt->packet, data + (h->caplen - pkt_len), len);
            pkt->packet[len] = 0;
            pkt->total_length = len;
         }

         pkt->ip_version = 6;
         pkt->ip_tos = ip->traffic_class;
         pkt->ip_proto = ip->next_hdr;
         pkt->ip_ttl = ip->hop_limit;
         pkt->ip_length = ip->payload_len;
         memcpy(pkt->src_ip.v6, (const char *) ip->src_addr, 16);
         memcpy(pkt->dst_ip.v6, (const char *) ip->dst_addr, 16);
         pkt->valid = true;
         parsed = true;
      } else if (headers->type == fpp_tcp_h) {
         /* TCP */
         struct tcp_h *tcp = (struct tcp_h *) headers->hdr;

         pkt->field_indicator |= (PCKT_TCP | PCKT_PAYLOAD);
         pkt->src_port = tcp->src_port;
         pkt->dst_port = tcp->dst_port;
         pkt->tcp_control_bits = tcp->flags;
      } else if (headers->type == fpp_udp_h) {
         /* UDP */
         struct udp_h *udp = (struct udp_h *) headers->hdr;

         pkt->field_indicator |= (PCKT_UDP | PCKT_PAYLOAD);
         pkt->src_port = udp->src_port;
         pkt->dst_port = udp->dst_port;
         pkt->tcp_control_bits = 0;
      } else if (headers->type == fpp_icmp_h) {
         struct icmp_h *icmp = (struct icmp_h *) headers->hdr;

         pkt->src_port = 0;
         pkt->dst_port = icmp->type_ * 256 + icmp->code;
         pkt->tcp_control_bits = 0;
         pkt->field_indicator |= PCKT_ICMP;
      } else if (headers->type == fpp_icmpv6_h) {
         struct icmp_h *icmp = (struct icmp_h *) headers->hdr;

         pkt->src_port = 0;
         pkt->dst_port = icmp->type_ * 256 + icmp->code;
         pkt->tcp_control_bits = 0;
         pkt->field_indicator |= PCKT_ICMP;
      } else if (headers->type == fpp_payload_h) {
         /* Payload */
         if (pkt->field_indicator & PCKT_PAYLOAD || parse_all) {
            struct payload_h *payload = (struct payload_h *) headers->hdr;

            uint32_t tmp = payload->header_offset - pkt_offset;
            pkt->payload_length = pkt->total_length - tmp;
            pkt->payload = pkt->packet + tmp;
         }
      } else if (headers->type == fpp_ipv6_hop_opt_h) {
         struct ipv6_hop_opt_h *ext = (struct ipv6_hop_opt_h *) headers->hdr;
         pkt->ip_proto = ext->next_hdr;
      } else if (headers->type == fpp_ipv6_dst_opt_h) {
         struct ipv6_dst_opt_h *ext = (struct ipv6_dst_opt_h *) headers->hdr;
         pkt->ip_proto = ext->next_hdr;
      } else if (headers->type == fpp_ipv6_routing_h) {
         struct ipv6_routing_h *ext = (struct ipv6_routing_h *) headers->hdr;
         pkt->ip_proto = ext->next_hdr;
      } else if (headers->type == fpp_ipv6_fragment_h) {
         struct ipv6_fragment_h *ext = (struct ipv6_fragment_h *) headers->hdr;
         pkt->ip_proto = ext->next_hdr;
      } else if (headers->type == fpp_ipv6_ah_h) {
         struct ipv6_ah_h *ext = (struct ipv6_ah_h *) headers->hdr;
         pkt->ip_proto = ext->next_hdr;
      }

      tmp = headers;
      headers = headers->next;

      free(tmp->hdr);
      free(tmp);
   }

   return;
}

/**
 * \brief Constructor.
 */
PcapReader::PcapReader() : handle(NULL), print_pcap_stats(false), netmask(PCAP_NETMASK_UNKNOWN)
{
}

/**
 * \brief Constructor.
 * \param [in] options Module options.
 */
PcapReader::PcapReader(const options_t &options) : handle(NULL), netmask(PCAP_NETMASK_UNKNOWN)
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
 * \param [in] parse_every_pkt Try to parse every captured packet.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int PcapReader::open_file(const string &file, bool parse_every_pkt)
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
   parse_all = parse_every_pkt;
   error_msg = "";
   return 0;
}

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \param [in] snaplen Snapshot length to be set on pcap handle.
 * \param [in] parse_every_pkt Try to parse every captured packet.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int PcapReader::init_interface(const string &interface, int snaplen, bool parse_every_pkt)
{
   if (handle != NULL) {
      error_msg = "Interface or pcap file is already opened.";
      return 1;
   }

   char errbuf[PCAP_ERRBUF_SIZE];
   errbuf[0] = 0;

   handle = pcap_open_live(interface.c_str(), snaplen, 1, READ_TIMEOUT, errbuf);
   if (handle == NULL) {
      error_msg = errbuf;
      return 2;
   }
   if (errbuf[0] != 0) {
      fprintf(stderr, "%s\n", errbuf); // Print warning.
   }

   if (pcap_datalink(handle) != DLT_EN10MB) {
      error_msg = "Unsupported data link type.";
      close();
      return 3;
   }

   bpf_u_int32 net;
   if (pcap_lookupnet(interface.c_str(), &net, &netmask, errbuf) != 0) {
      netmask = PCAP_NETMASK_UNKNOWN;
   }

   if (print_pcap_stats) {
      /* Print stats header. */
      printf("# recv   - number of packets received\n");
      printf("# drop   - number  of  packets dropped because there was no room in the operating system's buffer when they arrived, because packets weren't being read fast enough\n");
      printf("# ifdrop - number of packets dropped by the network interface or its driver\n\n");
      printf("recv\tdrop\tifdrop\n");
   }

   live_capture = true;
   parse_all = parse_every_pkt;
   error_msg = "";
   return 0;
}

/**
 * \brief Install BPF filter to pcap handle.
 * \param [in] filter_str String containing program.
 * \return 0 on success, non 0 on failure.
 */
int PcapReader::set_filter(const string &filter_str)
{
   if (handle == NULL) {
      error_msg = "No live capture or file opened.";
      return 1;
   }

   struct bpf_program filter;
   if (pcap_compile(handle, &filter, filter_str.c_str(), 0, netmask) == -1) {
      error_msg = "Couldn't parse filter " + string(filter_str) + ": " + string(pcap_geterr(handle));
      return 1;
   }
   if (pcap_setfilter(handle, &filter) == -1) {
      pcap_freecode(&filter);
      error_msg = "Couldn't install filter " + string(filter_str) + ": " + string(pcap_geterr(handle));
      return 1;
   }

   pcap_freecode(&filter);
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

   if (print_pcap_stats) {
      print_stats();
   }

   // Get pkt from network interface or file.
   ret = pcap_dispatch(handle, 1, packet_handler, (u_char *) (&packet));
   if (ret == 0) {
      // Read timeout occured or no more packets in file...
      return (live_capture ? 3 : 0);
   }

   if (ret == 1 && packet.valid) {
      // Packet is valid and ready to process by flow_cache.
      return 2;
   }
   if (ret < 0) {
      // Error occured.
      error_msg = pcap_geterr(handle);
   }
   return ret;
}
