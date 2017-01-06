/**
 * \file packet.h
 * \brief Structs/classes for communication between packet reader and flow cache
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdlib.h>

#include "ipaddr.h"
#include "flowifc.h"

#define MAXPCKTSIZE 1600

// Values of field presence indicator flags (field_indicator)
// (Names of the fields are inspired by IPFIX specification)
#define PCKT_PACKETFIELDINDICATOR               (0x1 << 0)
#define PCKT_TIMESTAMP                          (0x1 << 1)
#define PCKT_HASH                               (0x1 << 2)
#define PCKT_KEY                                (0x1 << 3)
#define PCKT_IPVERSION                          (0x1 << 4)
#define PCKT_PROTOCOLIDENTIFIER                 (0x1 << 5)
#define PCKT_IPLENGTH                           (0x1 << 6)
#define PCKT_IPCLASSOFSERVICE                   (0x1 << 7)
#define PCKT_IPTTL                              (0x1 << 8)
#define PCKT_SOURCEIPV4ADDRESS                  (0x1 << 9)
#define PCKT_DESTINATIONIPV4ADDRESS             (0x1 << 10)
#define PCKT_SOURCEIPV6ADDRESS                  (0x1 << 11)
#define PCKT_DESTINATIONIPV6ADDRESS             (0x1 << 12)
#define PCKT_SOURCETRANSPORTPORT                (0x1 << 13)
#define PCKT_DESTINATIONTRANSPORTPORT           (0x1 << 14)
#define PCKT_TCPCONTROLBITS                     (0x1 << 15)
#define PCKT_TRANSPORTPAYLOADPACKETSECTIONSIZE  (0x1 << 16)
#define PCKT_TRANSPORTPAYLOADPACKETSECTION      (0x1 << 17)
#define PCKT_ICMP                               (0x1 << 18)

// Some common sets of flags
#define PCKT_PCAP_MASK (PCKT_TIMESTAMP) // Bit 0

#define PCKT_INFO_MASK (\
   PCKT_HASH | \
   PCKT_KEY \
)

#define PCKT_IPV4_MASK (\
   PCKT_IPVERSION | \
   PCKT_PROTOCOLIDENTIFIER | \
   PCKT_IPLENGTH | \
   PCKT_IPCLASSOFSERVICE | \
   PCKT_IPTTL | \
   PCKT_SOURCEIPV4ADDRESS | \
   PCKT_DESTINATIONIPV4ADDRESS \
)

#define PCKT_IPV6_MASK (\
   PCKT_IPVERSION | \
   PCKT_PROTOCOLIDENTIFIER | \
   PCKT_IPCLASSOFSERVICE | \
   PCKT_SOURCEIPV6ADDRESS | \
   PCKT_DESTINATIONIPV6ADDRESS \
)

#define PCKT_TCP_MASK  (\
   PCKT_SOURCETRANSPORTPORT | \
   PCKT_DESTINATIONTRANSPORTPORT | \
   PCKT_TCPCONTROLBITS \
)

#define PCKT_UDP_MASK  (\
   PCKT_SOURCETRANSPORTPORT | \
   PCKT_DESTINATIONTRANSPORTPORT \
)

#define PCKT_PAYLOAD_MASK  (\
   PCKT_TRANSPORTPAYLOADPACKETSECTIONSIZE | \
   PCKT_TRANSPORTPAYLOADPACKETSECTION \
)

// TCP flags
#define TCP_FIN    0x01
#define TCP_SYN    0x02
#define TCP_RST    0x04
#define TCP_PUSH   0x08
#define TCP_ACK    0x10
#define TCP_URG    0x20

/**
 * \brief Structure for storing parsed packets up to transport layer.
 */
struct Packet : public Record {
   uint64_t    field_indicator;
   struct timeval timestamp;

   uint16_t    ethertype;

   uint8_t     ip_version;
   uint16_t    ip_length;
   uint8_t     ip_ttl;
   uint8_t     ip_proto;
   uint8_t     ip_tos;
   ipaddr_t    src_ip;
   ipaddr_t    dst_ip;

   uint16_t    src_port;
   uint16_t    dst_port;
   uint8_t     tcp_control_bits;

   uint16_t    total_length;
   char        *packet; /**< Array containing whole packet. */
   uint16_t    payload_length;
   char        *payload; /**< Pointer to packet payload section. */

   /**
    * \brief Constructor.
    */
   Packet() : total_length(0), packet(NULL), payload_length(0), payload(NULL)
   {
   }
};

#endif
