/**
 * \file httpplugin.h
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
struct FlowRecordExtHTTPReq : FlowRecordExt {
   char httpReqMethod[10];
   char httpReqHost[64];
   char httpReqUrl[128];
   char httpReqUserAgent[128];
   char httpReqReferer[128];

   /**
    * \brief Constructor.
    */
   FlowRecordExtHTTPReq() : FlowRecordExt(http_request)
   {
      httpReqMethod[0] = 0;
      httpReqHost[0] = 0;
      httpReqUrl[0] = 0;
      httpReqUserAgent[0] = 0;
      httpReqReferer[0] = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set_string(tmplt, record, F_HTTP_METHOD, httpReqMethod);
      ur_set_string(tmplt, record, F_HTTP_HOST, httpReqHost);
      ur_set_string(tmplt, record, F_HTTP_URL, httpReqUrl);
      ur_set_string(tmplt, record, F_HTTP_USER_AGENT, httpReqUserAgent);
      ur_set_string(tmplt, record, F_HTTP_REFERER, httpReqReferer);
   }
};

/**
 * \brief Flow record extension header for storing HTTP responses.
 */
struct FlowRecordExtHTTPResp : FlowRecordExt {
   uint16_t httpRespCode;
   char httpRespContentType[32];

   /**
    * \brief Constructor.
    */
   FlowRecordExtHTTPResp() : FlowRecordExt(http_response)
   {
      httpRespCode = 0;
      httpRespContentType[0] = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_HTTP_RESPONSE_CODE, httpRespCode);
      ur_set_string(tmplt, record, F_HTTP_CONTENT_TYPE, httpRespContentType);
   }
};

/**
 * \brief Flow cache plugin used to parse HTTP requests / responses.
 */
class HTTPPlugin : public FlowCachePlugin
{
public:
   HTTPPlugin(const options_t &options);
   void init();
   int post_create(FlowRecord &rec, const Packet &pkt);
   int pre_update(FlowRecord &rec, Packet &pkt);
   void post_update(FlowRecord &rec, const Packet &pkt);
   void pre_export(FlowRecord &rec);
   void finish();

private:
   bool parse_http_request(const char *data, int payload_len, FlowRecordExtHTTPReq *rec, bool create);
   bool parse_http_response(const char *data, int payload_len, FlowRecordExtHTTPResp *rec, bool create);
   int add_ext_http_request(const char *data, int payload_len, FlowRecord &rec);
   int add_ext_http_response(const char *data, int payload_len, FlowRecord &rec);
   bool valid_http_method(const char *method) const;

   bool statsout;          /**< Indicator whether to print stats when flow cache is finishing or not. */
   bool ignore_keep_alive; /**< Indicator whether to ignore HTTP keep-alive requests / responses or not. */
   bool flush_flow;        /**< Indicator whether to flush current flow or not. */
   uint32_t requests;      /**< Total number of parsed HTTP requests. */
   uint32_t responses;     /**< Total number of parsed HTTP responses. */
   uint32_t total;         /**< Total number of parsed HTTP packets. */
};

#endif
