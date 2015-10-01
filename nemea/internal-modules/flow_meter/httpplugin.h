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

   void close();
private:
   bool parse_http_request(const char *data, int payload_len, FlowRecordExtHTTPReq *rec);
   bool parse_http_response(const char *data, int payload_len, FlowRecordExtHTTPResp *rec);
   void add_ext_http_request(const char *data, int payload_len, FlowRecord &rec);
   void add_ext_http_response(const char *data, int payload_len, FlowRecord &rec);
   httpMethodEnum process_http_method(const char *method) const;

   bool statsout;
   bool keep_alive;
   uint32_t requests, responses, total;
};

#endif
