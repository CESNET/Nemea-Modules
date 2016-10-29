/**
 * \file flowifc.h
 * \brief Structs/classes for communication between flow cache and exporter
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

#ifndef FLOWRECORD_H
#define FLOWRECORD_H

/* Interface between flow cache and flow exporter. */

#include <stdint.h>
#include <stdlib.h>
#include <unirec/unirec.h>

#include "ipaddr.h"
#include "fields.h"

// Values of field presence indicator flags (field_indicator)
// (Names of the fields are inspired by IPFIX specification)
#define FLW_FLOWFIELDINDICATOR       (0x1 << 0)
#define FLW_HASH                     (0x1 << 1)
#define FLW_FLOWSTARTTIMESTAMP       (0x1 << 2)
#define FLW_FLOWENDTIMESTAMP         (0x1 << 3)
#define FLW_IPVERSION                (0x1 << 4)
#define FLW_PROTOCOLIDENTIFIER       (0x1 << 5)
#define FLW_IPCLASSOFSERVICE         (0x1 << 6)
#define FLW_IPTTL                    (0x1 << 7)
#define FLW_SOURCEIPV4ADDRESS        (0x1 << 8)
#define FLW_DESTINATIONIPV4ADDRESS   (0x1 << 9)
#define FLW_SOURCEIPV6ADDRESS        (0x1 << 10)
#define FLW_DESTINATIONIPV6ADDRESS   (0x1 << 11)
#define FLW_SOURCETRANSPORTPORT      (0x1 << 12)
#define FLW_DESTINATIONTRANSPORTPORT (0x1 << 13)
#define FLW_PACKETTOTALCOUNT         (0x1 << 14)
#define FLW_OCTETTOTALLENGTH         (0x1 << 15)
#define FLW_TCPCONTROLBITS           (0x1 << 16)
#define FLW_ICMP                     (0x1 << 17)

// Some common sets of flags
#define FLW_IPV4_MASK (\
   FLW_IPVERSION | \
   FLW_PROTOCOLIDENTIFIER | \
   FLW_IPCLASSOFSERVICE | \
   FLW_IPTTL | \
   FLW_SOURCEIPV4ADDRESS | \
   FLW_DESTINATIONIPV4ADDRESS \
)

#define FLW_IPV6_MASK (\
   FLW_IPVERSION | \
   FLW_PROTOCOLIDENTIFIER | \
   FLW_IPCLASSOFSERVICE | \
   FLW_SOURCEIPV6ADDRESS | \
   FLW_DESTINATIONIPV6ADDRESS \
)

#define FLW_TCP_MASK (\
   FLW_SOURCETRANSPORTPORT | \
   FLW_DESTINATIONTRANSPORTPORT | \
   FLW_TCPCONTROLBITS \
)

#define FLW_UDP_MASK (\
   FLW_SOURCETRANSPORTPORT | \
   FLW_DESTINATIONTRANSPORTPORT \
)

#define FLW_IPSTAT_MASK (\
   FLW_PACKETTOTALCOUNT | \
   FLW_OCTETTOTALLENGTH \
)

#define FLW_TIMESTAMPS_MASK (\
   FLW_FLOWSTARTTIMESTAMP | \
   FLW_FLOWENDTIMESTAMP \
)

#define FLW_PAYLOAD_MASK (\
   FLW_FLOWPAYLOADSTART | \
   FLW_FLOWPAYLOADSIZE \
)

/**
 * \brief Extension header type enum.
 */
enum extTypeEnum {
   http_request = 0,
   http_response,
   dns,
   sip,
   ntp,
   arp,
   /* Add extension header identifiers for your plugins here */
   EXTENSION_CNT
};

/**
 * \brief Flow record extension base struct.
 */
struct RecordExt {
   RecordExt *next; /**< Pointer to next extension */
   extTypeEnum extType; /**< Type of extension. */

   /**
    * \brief Constructor.
    * \param [in] type Type of extension.
    */
   RecordExt(extTypeEnum type) : next(NULL), extType(type)
   {
   }

   /**
    * \brief Fill unirec record with stored extension data.
    * \param [in] tmplt Unirec template.
    * \param [out] record Pointer to the unirec record.
    */
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
   }

   /**
    * \brief Virtual destructor.
    */
   virtual ~RecordExt()
   {
      if (next != NULL) {
         delete next;
      }
   }
};

struct Record {
   RecordExt *exts; /**< Extension headers. */

   /**
    * \brief Add new extension header.
    * \param [in] ext Pointer to the extension header.
    */
   void addExtension(RecordExt* ext)
   {
      if (exts == NULL) {
         exts = ext;
         exts->next = NULL;
      } else {
         RecordExt *ext_ptr = exts;
         while (ext_ptr->next != NULL) {
            ext_ptr = ext_ptr->next;
         }
         ext_ptr->next = ext;
         ext_ptr->next->next = NULL;
      }
   }

   /**
    * \brief Get given extension.
    * \param [in] extType Type of extension.
    * \return Pointer to the requested extension or NULL if extension is not present.
    */
   RecordExt *getExtension(extTypeEnum extType)
   {
      RecordExt *ext_ptr = exts;
      while (ext_ptr != NULL) {
         if (ext_ptr->extType == extType) {
            return ext_ptr;
         }
         ext_ptr = ext_ptr->next;
      }
      return NULL;
   }

   /**
    * \brief Remove extension headers.
    */
   void removeExtensions()
   {
      if (exts != NULL) {
         delete exts;
         exts = NULL;
      }
   }

   /**
    * \brief Constructor.
    */
   Record() : exts(NULL)
   {
   }

   /**
    * \brief Destructor.
    */
   virtual ~Record()
   {
      removeExtensions();
   }
};

/**
 * \brief Flow record struct constaining basic flow record data and extension headers.
 */
struct Flow : public Record {
   uint64_t field_indicator;
   struct timeval time_first;
   struct timeval time_last;
   uint8_t  ip_version;
   uint8_t  ip_proto;
   uint8_t  ip_tos;
   uint8_t  ip_ttl;
   ipaddr_t src_ip;
   ipaddr_t dst_ip;
   uint16_t src_port;
   uint16_t dst_port;
   uint32_t pkt_total_cnt;
   uint64_t octet_total_length;
   uint8_t  tcp_control_bits;
};

#endif
