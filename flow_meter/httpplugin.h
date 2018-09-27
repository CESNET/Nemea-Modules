/**
 * \file httpplugin.h
 * \brief Plugin for parsing HTTP traffic
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
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

#ifndef HTTPPLUGIN_H
#define HTTPPLUGIN_H

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fields.h>

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

using namespace std;

/**
 * \brief Flow record extension header for storing HTTP requests.
 */
struct RecordExtHTTPReq : RecordExt {
   char method[10];
   char host[64];
   char uri[128];
   char user_agent[128];
   char referer[128];

   /**
    * \brief Constructor.
    */
   RecordExtHTTPReq() : RecordExt(http_request)
   {
      method[0] = 0;
      host[0] = 0;
      uri[0] = 0;
      user_agent[0] = 0;
      referer[0] = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_HTTP_REQUEST_METHOD, method);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_HOST, host);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_URL, uri);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_AGENT, user_agent);
      ur_set_string(tmplt, record, F_HTTP_REQUEST_REFERER, referer);
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length, total_length = 0;

      length = strlen(user_agent);
      if (length + 1 > size) {
         return -1;
      }
      buffer[0] = length;
      memcpy(buffer + 1, user_agent, length);
      total_length = length + 1;

      length = strlen(method);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, method, length);
      total_length += length + 1;

      length = strlen(host);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, host, length);
      total_length += length + 1;

      length = strlen(referer);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, referer, length);
      total_length += length + 1;

      length = strlen(uri);
      if (total_length + length + 4 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, uri, length);
      total_length += length + 1;

      buffer[total_length] = 0;
      *(uint16_t *) (buffer + total_length + 1) = 0;
      total_length += 3;

      return total_length;
   }
};

/**
 * \brief Flow record extension header for storing HTTP responses.
 */
struct RecordExtHTTPResp : RecordExt {
   uint16_t code;
   char content_type[32];

   /**
    * \brief Constructor.
    */
   RecordExtHTTPResp() : RecordExt(http_response)
   {
      code = 0;
      content_type[0] = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_HTTP_RESPONSE_STATUS_CODE, code);
      ur_set_string(tmplt, record, F_HTTP_RESPONSE_CONTENT_TYPE, content_type);
   }
   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length = strlen(content_type);
      if (size - length - 8 < 0) {
         return -1;
      }

      buffer[0] = 0;
      buffer[1] = 0;
      buffer[2] = 0;
      buffer[3] = 0;
      buffer[4] = 0;
      buffer[5] = length;

      memcpy(buffer + 6, content_type, length);
      *(uint16_t *) (buffer + length + 6) = ntohs(code);

      return length + 8;
   }
};

/**
 * \brief Flow cache plugin used to parse HTTP requests / responses.
 */
class HTTPPlugin : public FlowCachePlugin
{
public:
   HTTPPlugin(const options_t &module_options);
   HTTPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   void finish();
   string get_unirec_field_string();
   const char **get_ipfix_string();

private:
   bool parse_http_request(const char *data, int payload_len, RecordExtHTTPReq *rec, bool create);
   bool parse_http_response(const char *data, int payload_len, RecordExtHTTPResp *rec, bool create);
   void add_ext_http_request(const char *data, int payload_len, Flow &rec);
   void add_ext_http_response(const char *data, int payload_len, Flow &rec);
   bool valid_http_method(const char *method) const;

   RecordExtHTTPReq *req;     /**< Preallocated request extension. */
   RecordExtHTTPResp *resp;   /**< Preallocated response extension. */
   bool print_stats;          /**< Print stats when flow cache is finishing. */
   bool flush_flow;           /**< Tell FlowCache to flush current Flow. */
   uint32_t requests;         /**< Total number of parsed HTTP requests. */
   uint32_t responses;        /**< Total number of parsed HTTP responses. */
   uint32_t total;            /**< Total number of parsed HTTP packets. */
};

#endif
