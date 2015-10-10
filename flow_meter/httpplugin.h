#ifndef HTTPPLUGIN_H
#define HTTPPLUGIN_H

#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

using namespace std;

struct FlowRecordExtHTTPReq : FlowRecordExt {
   char httpReqMethod[10];
   char httpReqHost[64];
   char httpReqUrl[128];
   char httpReqUserAgent[128];
   char httpReqReferer[128];

   FlowRecordExtHTTPReq() : FlowRecordExt(http_request)
   {
      httpReqMethod[0] = 0;
      httpReqHost[0] = 0;
      httpReqUrl[0] = 0;
      httpReqUserAgent[0] = 0;
      httpReqReferer[0] = 0;
   }
};

struct FlowRecordExtHTTPResp : FlowRecordExt {
   uint16_t httpRespCode;
   char httpRespContentType[32];

   FlowRecordExtHTTPResp() : FlowRecordExt(http_response)
   {
      httpRespCode = 0;
      httpRespContentType[0] = 0;
   }
};

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
   int process_http_method(const char *method) const;

   bool statsout;
   bool ignore_keep_alive;
   bool flush_flow;
   uint32_t requests, responses, total;
};

#endif
