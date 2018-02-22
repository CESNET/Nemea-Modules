/**
 * \file ipfixexporter.cpp
 * \brief Export flows in IPFIX format.
 *    The following code was used https://dior.ics.muni.cz/~velan/flowmon-export-ipfix/
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2012 Masaryk University, Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 * 3. Neither the name of the Masaryk University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
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
*/

#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <endian.h>
#include <config.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "flowcacheplugin.h"
#include "flowexporter.h"
#include "ipfixexporter.h"
#include "flowifc.h"
#include "ipfix-elements.h"

#define GCC_CHECK_PRAGMA ((__GNUC__ == 4 && 6 <= __GNUC_MINOR__) || 4 < __GNUC__)

#define FIELD_EN_INT(EN, ID, LEN, SRC) EN
#define FIELD_ID_INT(EN, ID, LEN, SRC) ID
#define FIELD_LEN_INT(EN, ID, LEN, SRC) LEN
#define FIELD_SOURCE_INT(EN, ID, LEN, SRC) SRC

#define FIELD_EN(A) A(FIELD_EN_INT)
#define FIELD_ID(A) A(FIELD_ID_INT)
#define FIELD_LEN(A) A(FIELD_LEN_INT)
#define FIELD_SOURCE(A) A(FIELD_SOURCE_INT)

#define F(ENUMBER, EID, LENGTH, SOURCE) ENUMBER, EID, LENGTH
#define X(FIELD) {#FIELD, FIELD(F)},

/**
 * Copy value into buffer and swap bytes if needed.
 *
 * \param[out] TARGET pointer to the first byte of the current field in buffer
 * \param[in] SOURCE pointer to source of data
 * \param[in] LENGTH size of data in bytes
 */
#define IPFIX_FILL_FIELD(TARGET, FIELD) do { \
   if (FIELD_LEN(FIELD) == 1) { \
      *((uint8_t *) TARGET) = *((uint8_t *) FIELD_SOURCE(FIELD)); \
   } else if (FIELD_LEN(FIELD) == 2) { \
      *((uint16_t *) TARGET) = htons(*((uint16_t *) FIELD_SOURCE(FIELD))); \
   } else if ((FIELD_EN(FIELD) == 0) && \
              ((FIELD_ID(FIELD) == FIELD_ID(L3_IPV4_ADDR_SRC)) || (FIELD_ID(FIELD) == FIELD_ID(L3_IPV4_ADDR_DST)))) { \
      *((uint32_t *) TARGET) = *((uint32_t *) FIELD_SOURCE(FIELD)); \
   } else if (FIELD_LEN(FIELD) == 4) { \
      *((uint32_t *) TARGET) = htonl(*((uint32_t *) FIELD_SOURCE(FIELD))); \
   } else if (FIELD_LEN(FIELD) == 8) { \
      *((uint64_t *) TARGET) = swap_uint64(*((uint64_t *) FIELD_SOURCE(FIELD))); \
   } else { \
      memcpy(TARGET, (void *) FIELD_SOURCE(FIELD), FIELD_LEN(FIELD)); \
   } \
   TARGET += FIELD_LEN(FIELD); \
} while (0)

/*
 * IPFIX template fields.
 *
 * name enterprise-number element-id length
 */
template_file_record_t ipfix_fields[][1] = {
   IPFIX_ENABLED_TEMPLATES(X)
   NULL
};

/* Packet template. */
const char *packet_tmplt[] = {
   PACKET_TMPLT(IPFIX_FIELD_NAMES)
   NULL
};

/* Basic IPv4 template. */
const char *basic_tmplt_v4[] = {
   BASIC_TMPLT_V4(IPFIX_FIELD_NAMES)
   NULL
};

/* Basic IPv6 template. */
const char *basic_tmplt_v6[] = {
   BASIC_TMPLT_V6(IPFIX_FIELD_NAMES)
   NULL
};

IPFIXExporter::IPFIXExporter()
{
   templateArray = NULL;
   templates = NULL;
   templatesDataSize = 0;
   tmpltMapping = NULL;
   basic_ifc_num = -1;
   verbose = false;

   sequenceNum = 0;
   exportedPackets = 0;
   fd = -1;
   addrinfo = NULL;

   host = "";
   port = "";
   protocol = IPPROTO_TCP;
   ip = AF_UNSPEC; //AF_INET;
   flags = 0;
   reconnectTimeout = RECONNECT_TIMEOUT;
   lastReconnect = 0;
   odid = 0;
   templateRefreshTime = TEMPLATE_REFRESH_TIME;
   templateRefreshPackets = TEMPLATE_REFRESH_PACKETS;
}

IPFIXExporter::~IPFIXExporter()
{
   shutdown();
}

/**
 * \brief Function called at exporter shutdown
 */
void IPFIXExporter::shutdown()
{
   /* Close the connection */
   if (fd != -1) {
      flush();

      close(fd);
      freeaddrinfo(addrinfo);
      fd = -1;
   }
   if (templateArray) {
      delete [] templateArray;
      templateArray = NULL;
   }

   template_t *tmp = templates;
   while (tmp != NULL) {
      templates = templates->next;
      free(tmp);
      tmp = templates;
   }
   tmp = NULL;

   if (tmpltMapping) {
      delete [] tmpltMapping;
      tmpltMapping = NULL;
   }
}

int IPFIXExporter::export_flow(Flow &flow)
{
   RecordExt *ext = flow.exts;
   template_t *tmplt;
   int ipv6_tmplt = 0;

   if (flow.ip_version == 6) {
      ipv6_tmplt = 1;
   }

   if (ext == NULL && basic_ifc_num >= 0) {
      tmplt = templateArray[basic_ifc_num * 2 + ipv6_tmplt];

      int length = fill_basic_flow(flow, tmplt);
      if (length == -1) {
         send_templates();
         send_data();

         length = fill_basic_flow(flow, tmplt);
      }
      tmplt->bufferSize += length;
      tmplt->recordCount++;
   } else {
      while (ext != NULL) {
         int tmplt_num = tmpltMapping[ext->extType];
         if (tmplt_num >= 0) {
            tmplt = templateArray[tmplt_num * 2 + ipv6_tmplt];

            int length_basic = fill_basic_flow(flow, tmplt);
            if (length_basic == -1) {
               send_templates();
               send_data();

               length_basic = fill_basic_flow(flow, tmplt);
            }

            int length_ext = ext->fillIPFIX(tmplt->buffer + tmplt->bufferSize + length_basic,
                              TEMPLATE_BUFFER_SIZE - tmplt->bufferSize - length_basic);
            if (length_ext == -1) {
               send_templates();
               send_data();

               length_basic = fill_basic_flow(flow, tmplt);
               length_ext = ext->fillIPFIX(tmplt->buffer + tmplt->bufferSize + length_basic,
                              TEMPLATE_BUFFER_SIZE - tmplt->bufferSize - length_basic);
            }

            tmplt->bufferSize += length_basic + length_ext;
            tmplt->recordCount++;
         }
         ext = ext->next;
      }
   }

   return 0;
}

int IPFIXExporter::export_packet(Packet &pkt)
{
   RecordExt *ext = pkt.exts;
   template_t *tmplt;

   while (ext != NULL) {
      int tmplt_num = tmpltMapping[ext->extType];
      if (tmplt_num >= 0) {
         tmplt = templateArray[tmplt_num * 2];

         int length_packet = fill_packet_fields(pkt, tmplt);
         if (length_packet == -1) {
            send_templates();
            send_data();

            length_packet = fill_packet_fields(pkt, tmplt);
         }

         int length_ext = ext->fillIPFIX(tmplt->buffer + tmplt->bufferSize + length_packet,
               TEMPLATE_BUFFER_SIZE - tmplt->bufferSize - length_packet);
         if (length_ext == -1) {
            send_templates();
            send_data();

            length_packet = fill_packet_fields(pkt, tmplt);
            length_ext = ext->fillIPFIX(tmplt->buffer + tmplt->bufferSize + length_packet,
                  TEMPLATE_BUFFER_SIZE - tmplt->bufferSize - length_packet);
         }

         tmplt->bufferSize += length_packet + length_ext;
         tmplt->recordCount++;
      }
      ext = ext->next;
   }
   return 0;
}

/**
 * \brief Exporter initialization
 *
 * @param params plugins Flowcache export plugins.
 * @param basic_num Index of basic pseudoplugin
 * @param odid Exporter identification
 * @param host Collector address
 * @param port Collector port
 * @param udp Use UDP instead of TCP
 * @return Returns 0 on succes, non 0 otherwise.
 */
int IPFIXExporter::init(const vector<FlowCachePlugin *> &plugins, int basic_num, uint32_t odid, string host, string port, bool udp, bool verbose, uint8_t dir)
{
   int ret, templateCnt;

   if (verbose) {
      fprintf(stderr, "VERBOSE: IPFIX export plugin init start\n");
   }

   /* Init plugin configuration */
   templateCnt = EXTENSION_CNT * 2 + 2;
   templateArray = new template_t*[templateCnt];
   for (int i = 0; i < templateCnt; i++) {
      templateArray[i] = NULL;
   }
   this->verbose = verbose;
   this->host = host;
   this->port = port;
   this->odid = odid;
   basic_ifc_num = basic_num;
   this->dir_bit_field = dir;

   if (udp) {
      protocol = IPPROTO_UDP;
   }

   if (basic_num >= 0) {
      templateArray[basic_ifc_num * 2] = create_template(basic_tmplt_v4, NULL);
      templateArray[basic_ifc_num * 2 + 1] = create_template(basic_tmplt_v6, NULL);

      if (templateArray[basic_ifc_num * 2] == NULL || templateArray[basic_ifc_num * 2 + 1] == NULL) {
         fprintf(stderr, "IPFIX template creation failed.\n");
         shutdown();
         return 1;
      }
   }

   tmpltMapping = new int[EXTENSION_CNT];
   for (int i = 0; i < EXTENSION_CNT; i++) {
      tmpltMapping[i] = -1;
   }
   for (unsigned int i = 0; i < plugins.size(); i++) {
      FlowCachePlugin * const tmp = plugins[i];
      vector<plugin_opt> &opts = tmp->get_options();
      int ifc = -1;

      for (unsigned int j = 0; j < opts.size(); j++) { // Create plugin extension id -> output interface mapping.
         tmpltMapping[opts[j].ext_type] = opts[j].out_ifc_num;
         ifc = opts[j].out_ifc_num;
      }

      if (ifc >= 0) {
         if (tmp->include_basic_flow_fields()) {
            templateArray[ifc * 2] = create_template(basic_tmplt_v4, tmp->get_ipfix_string());
            templateArray[ifc * 2 + 1] = create_template(basic_tmplt_v6, tmp->get_ipfix_string());
         } else {
            templateArray[ifc * 2] = create_template(packet_tmplt, tmp->get_ipfix_string());
         }

         if (templateArray[ifc * 2] == NULL || (tmp->include_basic_flow_fields() &&
             templateArray[ifc * 2 + 1] == NULL)) {
            fprintf(stderr, "IPFIX template creation failed.\n");
            shutdown();
            return 1;
         }
      }
   }

   ret = connect_to_collector();
   if (ret == 1) {
      return 1;
   } else if (ret == 2) {
      lastReconnect = time(NULL);
   }

   if (verbose) {
      fprintf(stderr, "VERBOSE: IPFIX export plugin init end\n");
   }
   return 0;
}

/**
 * \brief Initialise buffer for record with Data Set Header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Set ID               |          Length               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * @param tmpl Template to init
 */
void IPFIXExporter::init_template_buffer(template_t *tmpl)
{
   *((uint16_t *) &tmpl->buffer[0]) = htons(tmpl->id);
   /* Length will be updated later */
   /* *((uint16_t *) &tmpl->buffer[2]) = htons(0); */
   tmpl->bufferSize = 4;
}

/**
 * \brief Fill ipfix template set header to memory specified by pointer
 *
 * @param ptr Pointer to memory to fill. Should be at least 4 bytes long
 * @param size Size of the template set including set header
 * @return size of the template set header
 */
int IPFIXExporter::fill_template_set_header(char *ptr, uint16_t size)
{
   ipfix_template_set_header_t *header = (ipfix_template_set_header_t *) ptr;

   header->id = htons(TEMPLATE_SET_ID);
   header->length = htons(size);

   return IPFIX_SET_HEADER_SIZE;
}

/**
 * \brief Check whether timeouts for template expired and set exported flag accordingly
 *
 * @param tmpl Template to check
 */
void IPFIXExporter::check_template_lifetime(template_t *tmpl)
{
   if (templateRefreshTime != 0 &&
         (time_t) (templateRefreshTime + tmpl->exportTime) <= time(NULL)) {
      if (verbose) {
         fprintf(stderr, "VERBOSE: Template %i refresh time expired (%is)\n", tmpl->id, templateRefreshTime);
      }
      tmpl->exported = 0;
   }

   if (templateRefreshPackets != 0 &&
         templateRefreshPackets + tmpl->exportPacket <= exportedPackets) {
      if (verbose) {
         fprintf(stderr, "VERBOSE: Template %i refresh packets expired (%i packets)\n", tmpl->id, templateRefreshPackets);
      }
      tmpl->exported = 0;
   }
}

/**
 * \brief Fill ipfix header to memory specified by pointer
 *
 * @param ptr Pointer to memory to fill. Should be at least 16 bytes long
 * @param size Size of the IPFIX packet not including the header.
 * @return Returns size of the header
 */
int IPFIXExporter::fill_ipfix_header(char *ptr, uint16_t size)
{
   ipfix_header_t *header = (ipfix_header_t *)ptr;

   header->version = htons(IPFIX_VERISON);
   header->length = htons(size);
   header->exportTime = htonl(time(NULL));
   header->sequenceNumber = htonl(sequenceNum);
   header->observationDomainId = htonl(odid);

   return IPFIX_HEADER_SIZE;
}

/**
 * \brief Get template record from template file by name
 *
 * @param name Name of the record to find
 * @return Template File Record with matching name or NULL when non exists
 */
template_file_record_t *IPFIXExporter::get_template_record_by_name(const char *name)
{
   template_file_record_t *tmpFileRecord = *ipfix_fields;

   if (name == NULL) {
      if (verbose) {
         fprintf(stderr, "VERBOSE: Cannot get template for NULL name\n");
      }
      return NULL;
   }

   while (tmpFileRecord && tmpFileRecord->name) {
      if (strcmp(name, tmpFileRecord->name) == 0) {
         return tmpFileRecord;
      }
      tmpFileRecord++;
   }

   return NULL;
}

/**
 * \brief Set all templates as expired
 */
void IPFIXExporter::expire_templates()
{
   template_t *tmp;
   for (tmp = templates; tmp != NULL; tmp = tmp->next) {
      tmp->exported = 0;
      if (protocol == IPPROTO_UDP) {
         tmp->exportTime = time(NULL);
         tmp->exportPacket = exportedPackets;
      }
   }
}

/**
 * \brief Create new template based on given record
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Template ID (> 255)      |         Field Count           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * @param tmplt Template fields string
 * @param ext Template extension fields string
 * @return Created template on success, NULL otherwise
 */
template_t *IPFIXExporter::create_template(const char **tmplt, const char **ext)
{
   uint16_t maxID = FIRST_TEMPLATE_ID, len;
   template_t *tmpTemplate = templates, *newTemplate;
   const char **tmp = tmplt;

   /* Create new template structure */
   newTemplate = (template_t *) malloc(sizeof(template_t));
   if (!newTemplate) {
      fprintf(stderr, "Error: Not enough memory for IPFIX template.\n");
      return NULL;
   }
   newTemplate->fieldCount = 0;
   newTemplate->recordCount = 0;

   /* Set template ID to maximum + 1 */
   while (tmpTemplate != NULL) {
      if (tmpTemplate->id >= maxID) maxID = tmpTemplate->id + 1;
      tmpTemplate = tmpTemplate->next;
   }
   newTemplate->id = maxID;
   ((uint16_t *) newTemplate->templateRecord)[0] = htons(newTemplate->id);

   if (verbose) {
      fprintf(stderr, "VERBOSE: Creating new template id %u\n", newTemplate->id);
   }

   /* Template header size */
   newTemplate->templateSize = 4;

   while (1) {
      while (tmp && *tmp) {
         /* Find appropriate template file record */
         template_file_record_t *tmpFileRecord = get_template_record_by_name(*tmp);
         if (tmpFileRecord != NULL) {
            if (verbose) {
               fprintf(stderr, "VERBOSE: Adding template field name=%s EN=%u ID=%u len=%d\n",
                  tmpFileRecord->name, tmpFileRecord->enterpriseNumber, tmpFileRecord->elementID, tmpFileRecord->length);
            }

            /* Set information element ID */
            uint16_t eID = tmpFileRecord->elementID;
            if (tmpFileRecord->enterpriseNumber != 0) {
               eID |= 0x8000;
            }
            *((uint16_t *) &newTemplate->templateRecord[newTemplate->templateSize]) = htons(eID);

            /* Set element length */
            if (tmpFileRecord->length == 0) {
               fprintf(stderr, "Error: Template field cannot be zero length.\n");
               free(newTemplate);
               return NULL;
            } else {
               len = tmpFileRecord->length;
            }
            *((uint16_t *) &newTemplate->templateRecord[newTemplate->templateSize + 2]) = htons(len);

            /* Update template size */
            newTemplate->templateSize += 4;

            /* Add enterprise number if required */
            if (tmpFileRecord->enterpriseNumber != 0) {
               *((uint32_t *) &newTemplate->templateRecord[newTemplate->templateSize]) =
                  htonl(tmpFileRecord->enterpriseNumber);
               newTemplate->templateSize += 4;
            }

            /* Increase field count */
            newTemplate->fieldCount++;
         } else {
            fprintf(stderr, "Error: Cannot find field specification for name %s\n", *tmp);
            free(newTemplate);
            return NULL;
         }

         tmp++;
      }

      if (ext == NULL) {
         break;
      }
      tmp = ext;
      ext = NULL;
   }

   /* Set field count */
   ((uint16_t *) newTemplate->templateRecord)[1] = htons(newTemplate->fieldCount);

   /* Initialize buffer for records */
   init_template_buffer(newTemplate);

   /* Update total template size */
   templatesDataSize += newTemplate->bufferSize;

   /* The template was not exported yet */
   newTemplate->exported = 0;
   newTemplate->exportTime = time(NULL);
   newTemplate->exportPacket = exportedPackets;

   /* Add the new template to the list */
   newTemplate->next = templates;
   templates = newTemplate;

   return newTemplate;
}

/**
 * \brief Creates template packet
 *
 * Sets used templates as exported!
 *
 * @param packet Pointer to packet to fill
 * @return IPFIX packet with templates to export or NULL on failure
 */
uint16_t IPFIXExporter::create_template_packet(ipfix_packet_t *packet)
{
   template_t *tmp = templates;
   uint16_t totalSize = 0;
   char *ptr;

   /* Get total size */
   while (tmp != NULL) {
      /* Check UDP template lifetime */
      if (protocol == IPPROTO_UDP) {
         check_template_lifetime(tmp);
      }
      if (tmp->exported == 0) {
         totalSize += tmp->templateSize;
      }
      tmp = tmp->next;
   }

   /* Check that there are templates to export */
   if (totalSize == 0) {
      return 0;
   }

   totalSize += IPFIX_HEADER_SIZE + IPFIX_SET_HEADER_SIZE;

   /* Allocate memory for the packet */
   packet->data = (char *) malloc(sizeof(char)*(totalSize));
   if (!packet->data) {
      return 0;
   }
   ptr = packet->data;

   /* Create ipfix message header */
   ptr += fill_ipfix_header(ptr, totalSize);
   /* Create template set header */
   ptr += fill_template_set_header(ptr, totalSize - IPFIX_HEADER_SIZE);


   /* Copy the templates to the packet */
   tmp = templates;
   while (tmp != NULL) {
      if (tmp->exported == 0) {
         memcpy(ptr, tmp->templateRecord, tmp->templateSize);
         ptr += tmp->templateSize;
         /* Set the templates as exported, store time and serial number */
         tmp->exported = 1;
         tmp->exportTime = time(NULL);
         tmp->exportPacket = exportedPackets;
      }
      tmp = tmp->next;
   }

   packet->length = totalSize;
   packet->flows = 0;

   return totalSize;
}

/**
 * \brief Creates data packet from template buffers
 *
 * Removes the data from the template buffers
 *
 * @param packet Pointer to packet to fill
 * @return length of the IPFIX data packet on success, 0 otherwise
 */
uint16_t IPFIXExporter::create_data_packet(ipfix_packet_t *packet)
{
   template_t *tmp = templates;
   uint16_t totalSize = IPFIX_HEADER_SIZE; /* Include IPFIX header to total size */
   uint32_t deltaSequenceNum = 0; /* Number of exported records in this packet */
   char *ptr;

   /* Start adding data after the header */
   ptr = packet->data + totalSize;

   /* Copy the data sets to the packet */
   templatesDataSize = 0; /* Erase total data size */
   while (tmp != NULL) {
      /* Add only templates with data that fits to one packet */
      if (tmp->recordCount > 0 && totalSize + tmp->bufferSize <= PACKET_DATA_SIZE) {
         memcpy(ptr, tmp->buffer, tmp->bufferSize);
         /* Set SET length */
         ((ipfix_template_set_header_t *) ptr)->length = htons(tmp->bufferSize);
         if (verbose) {
            fprintf(stderr, "VERBOSE: Adding template %i of length %i to data packet\n", tmp->id, tmp->bufferSize);
         }
         ptr += tmp->bufferSize;
         /* Count size of the data copied to buffer */
         totalSize += tmp->bufferSize;
         /* Delete data from buffer */
         tmp->bufferSize = IPFIX_SET_HEADER_SIZE;

         /* Store number of exported records  */
         deltaSequenceNum += tmp->recordCount;
         tmp->recordCount = 0;
      }
      /* Update total data size, include empty template buffers (only set headers) */
      templatesDataSize += tmp->bufferSize;
      tmp = tmp->next;
   }

   /* Check that there are packets to export */
   if (totalSize == IPFIX_HEADER_SIZE) {
      return 0;
   }

   /* Create ipfix message header at the beginning */
   //fill_ipfix_header(buff, totalSize);
   fill_ipfix_header(packet->data, totalSize);

   /* Fill number of flows and size of the packet */
   packet->flows = deltaSequenceNum;
   packet->length = totalSize;

   return totalSize;
}

/**
 * \brief Send all new templates to collector
 */
void IPFIXExporter::send_templates()
{
   ipfix_packet_t pkt;

   /* Send all new templates */
   if (create_template_packet(&pkt)) {
      /* Send template packet */
      /* After error, the plugin sends all templates after reconnection,
       * so we need not concern about it here */
      send_packet(&pkt);

      free(pkt.data);
   }
}

/**
 * \brief Send data in all buffers to collector
 */
void IPFIXExporter::send_data()
{
   char buffer[PACKET_DATA_SIZE];
   ipfix_packet_t pkt;
   pkt.data = buffer;

   /* Send all new templates */
   if (create_data_packet(&pkt)) {
      if (send_packet(&pkt) == 1) {
         /* Collector reconnected, resend the packet */
         send_packet(&pkt);
      }
   }
}

/**
 * \brief Export stored flows.
 */
void IPFIXExporter::flush()
{
   /* Send all new templates */
   send_templates();

   /* Send the data packet */
   send_data();
}

/**
 * \brief Sends packet using UDP or TCP as defined in plugin configuration
 *
 * When the collector disconnects, tries to reconnect and resend the data
 *
 * \param packet Packet to send
 * \return 0 on success, -1 on socket error, 1 when data needs to be resent (after reconnect)
 */
int IPFIXExporter::send_packet(ipfix_packet_t *packet)
{
   int ret; /* Return value of sendto */
   int sent = 0; /* Sent data size */

   /* Check that connection is OK or drop packet */
   if (reconnect()) {
      return -1;
   }

   /* sendto() does not guarantee that everything will be send in one piece */
   while (sent < packet->length) {
      /* Send data to collector (TCP and SCTP ignores last two arguments) */
      ret = sendto(fd, (void *) (packet->data + sent), packet->length - sent, 0,
            addrinfo->ai_addr, addrinfo->ai_addrlen);

      /* Check that the data were sent correctly */
      if (ret == -1) {
         switch (errno) {
         case 0: break; /* OK */
         case ECONNRESET:
         case EINTR:
         case ENOTCONN:
         case ENOTSOCK:
         case EPIPE:
         case EHOSTUNREACH:
         case ENETDOWN:
         case ENETUNREACH:
         case ENOBUFS:
         case ENOMEM:

            /* The connection is broken */
            if (verbose) {
               fprintf(stderr, "VERBOSE: Collector closed connection\n");
            }

            /* free resources */
            close(fd);
            fd = -1;
            freeaddrinfo(addrinfo);

            /* Set last connection try time so that we would reconnect immediatelly */
            lastReconnect = 1;

            /* Reset the sequences number since it is unique per connection */
            sequenceNum = 0;
            ((ipfix_header_t *) packet->data)->sequenceNumber = 0; /* no need to change byteorder of 0 */

            /* Say that we should try to connect and send data again */
            return 1;
         default:
            /* Unknown error */
            if (verbose) {
               perror("VERBOSE: Cannot send data to collector");
            }
            return -1;
         }
      }

      /* No error from sendto(), add sent data count to total */
      sent += ret;
   }

   /* Update sequence number for next packet */
   sequenceNum += packet->flows;

   /* Increase packet counter */
   exportedPackets++;

   if (verbose) {
      fprintf(stderr, "VERBOSE: Packet (%" PRIu64 ") sent to %s on port %s. Next sequence number is %i\n",
            exportedPackets, host.c_str(), port.c_str(), sequenceNum);
   }

   return 0;
}

/**
 * \brief Create connection to collector
 *
 * The created socket is stored in conf->socket, addrinfo in conf->addrinfo
 * Addrinfo is freed up and socket is disconnected on error
 *
 * @return 0 on success, 1 on socket error or 2 when target is not listening
 */
int IPFIXExporter::connect_to_collector()
{
   struct addrinfo hints, *tmp;
   int err;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = ip;
   hints.ai_protocol = protocol;
   hints.ai_flags = AI_ADDRCONFIG | flags;

   err = getaddrinfo(host.c_str(), port.c_str(), &hints, &addrinfo);
   if (err) {
      if (err == EAI_SYSTEM) {
         fprintf(stderr, "Cannot get server info: %s\n", strerror(errno));
      } else {
         fprintf(stderr, "Cannot get server info: %s\n", gai_strerror(err));
      }
      return 1;
   }

   /* Try addrinfo strucutres one by one */
   for (tmp = addrinfo; tmp != NULL; tmp = tmp->ai_next) {

      if (tmp->ai_family != AF_INET && tmp->ai_family != AF_INET6) {
         continue;
      }

      /* Print information about target address */
      char buff[INET6_ADDRSTRLEN];
      inet_ntop(tmp->ai_family,
            (tmp->ai_family == AF_INET) ?
                  (void *) &((struct sockaddr_in *) tmp->ai_addr)->sin_addr :
                  (void *) &((struct sockaddr_in6 *) tmp->ai_addr)->sin6_addr,
            (char *) &buff, sizeof(buff));

      if (verbose) {
         fprintf(stderr, "VERBOSE: Connecting to IP %s\n", buff);
         fprintf(stderr, "VERBOSE: Socket configuration: AI Family: %i, AI Socktype: %i, AI Protocol: %i\n",
               tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
      }

      /* create socket */
      fd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
      if (fd == -1) {
         if (verbose) {
            perror("VERBOSE: Cannot create new socket");
         }
         continue;
      }

      /* connect to server with TCP and SCTP */
      if (protocol != IPPROTO_UDP &&
            connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
         if (verbose) {
            perror("VERBOSE: Cannot connect to collector");
         }
         close(fd);
         fd = -1;
         continue;
      }

      /* Connected, meaningless for UDP */
      if (protocol != IPPROTO_UDP) {
         if (verbose) {
            fprintf(stderr, "VERBOSE: Successfully connected to collector\n");
         }
      }
      break;
   }

   /* Return error when all addrinfo structures were tried*/
   if (tmp == NULL) {
      /* Free allocated resources */
      freeaddrinfo(addrinfo);
      return 2;
   }

   return 0;
}

/**
 * \brief Checks that connection is OK or tries to reconnect
 *
 * @return 0 when connection is OK or reestablished, 1 when not
 */
int IPFIXExporter::reconnect()
{
   /* Check for broken connection */
   if (lastReconnect != 0) {
      /* Check whether we need to attempt reconnection */
      if ((time_t) (lastReconnect + reconnectTimeout) <= time(NULL)) {
         /* Try to reconnect */
         if (connect_to_collector() == 0) {
            lastReconnect = 0;
            /* Resend all templates */
            expire_templates();
            send_templates();
         } else {
            /* Set new reconnect time and drop packet */
            lastReconnect = time(NULL);
            return 1;
         }
      } else {
         /* Timeout not reached, drop packet */
         return 1;
      }
   }

   return 0;
}

/**
 * \brief Swaps byte order of 8 B value.
 * @param value Value to swap
 * @return Swapped value
 */
#if BYTEORDER == 4321 /* Big endian */
static inline uint64_t swap_uint64(uint64_t value)
{
   return value;
}
#else
static inline uint64_t swap_uint64(uint64_t value)
{
   value = ((value << 8) & 0xFF00FF00FF00FF00ULL ) | ((value >> 8) & 0x00FF00FF00FF00FFULL );
   value = ((value << 16) & 0xFFFF0000FFFF0000ULL ) | ((value >> 16) & 0x0000FFFF0000FFFFULL );
   return (value << 32) | (value >> 32);
}
#endif

/**
 * \brief Fill template buffer with packet fields.
 * @param pkt Packet
 * @param tmplt Template containing buffer
 * @return Number of written bytes or -1 if buffer is not big enough
 */
int IPFIXExporter::fill_packet_fields(Packet &pkt, template_t *tmplt)
{
   uint8_t *buffer;

   if (tmplt->bufferSize + 22 > TEMPLATE_BUFFER_SIZE) {
      return -1;
   }

   buffer = tmplt->buffer + tmplt->bufferSize;
   memcpy(buffer, pkt.packet, 6);
   memcpy(buffer + 6, pkt.packet + 6, 6);
   *(uint16_t *) (buffer + 12) = ntohs(pkt.ethertype);
   *(uint64_t *) (buffer + 14) = swap_uint64(((uint64_t) pkt.timestamp.tv_sec * 1000) + (uint64_t) (pkt.timestamp.tv_usec / 1000));

   return 22;
}


#define GEN_FIELDS_SUMLEN_INT(FIELD) FIELD_LEN(FIELD) +
#define GEN_FILLFIELDS_INT(TMPLT) IPFIX_FILL_FIELD(p, TMPLT);
#define GEN_FILLFIELDS_MAXLEN(TMPLT) IPFIX_FILL_FIELD(p, TMPLT);


#define GENERATE_FILL_FIELDS_V4() do { \
BASIC_TMPLT_V4(GEN_FILLFIELDS_INT) \
} while (0)

#define GENERATE_FILL_FIELDS_V6() do { \
BASIC_TMPLT_V6(GEN_FILLFIELDS_INT) \
} while (0)

#define GENERATE_FIELDS_SUMLEN(TMPL) TMPL(GEN_FIELDS_SUMLEN_INT) 0

/**
 * \brief Fill template buffer with flow.
 * @param flow Flow
 * @param tmplt Template containing buffer
 * @return Number of written bytes or -1 if buffer is not big enough
 */
int IPFIXExporter::fill_basic_flow(Flow &flow, template_t *tmplt)
{
   uint8_t *buffer, *p;
   int length;
   uint64_t temp;

   buffer = tmplt->buffer + tmplt->bufferSize;
   p = buffer;
   if (flow.ip_version == 4) {
      if (tmplt->bufferSize + GENERATE_FIELDS_SUMLEN(BASIC_TMPLT_V4) > TEMPLATE_BUFFER_SIZE) {
         return -1;
      }

      /* Temporary disable warnings about breaking string-aliasing, since it is produced by
       * if-branches that are never going to be used - generated by C-preprocessor.
       */
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif
		/* Generate code for copying values of IPv4 template into IPFIX message. */
      GENERATE_FILL_FIELDS_V4();
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic pop
#endif

   } else {
      if (tmplt->bufferSize + GENERATE_FIELDS_SUMLEN(BASIC_TMPLT_V6) > TEMPLATE_BUFFER_SIZE) {
         return -1;
      }

      /* Temporary disable warnings about breaking string-aliasing, since it is produced by
       * if-branches that are never going to be used - generated by C-preprocessor.
       */
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif
		/* Generate code for copying values of IPv6 template into IPFIX message. */
      GENERATE_FILL_FIELDS_V6();
#if GCC_CHECK_PRAGMA
# pragma GCC diagnostic pop
#endif
   }

   length = p - buffer;

   return length;
}

