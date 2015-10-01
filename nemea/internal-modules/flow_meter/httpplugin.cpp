#include <iostream>
#include <stdlib.h>
#include <string.h>

#include "packet.h"
#include "flowifc.h"
#include "httpplugin.h"

//#define DEBUG_HTTP
//#define DEBUG_HTTP_PAYLOAD_PREVIEW
using namespace std;

#define HTTP_LINE_DELIMITER "\r\n"
#define HTTP_HEADER_DELIMITER ':'

HTTPPlugin::HTTPPlugin(const options_t &options) : statsout(options.statsout), requests(0), responses(0), total(0)
{
}

void HTTPPlugin::init()
{
}

int HTTPPlugin::post_create(FlowRecord &rec, const Packet &pkt)
{
   if (pkt.sourceTransportPort == 80) {
      add_ext_http_response(pkt.transportPayloadPacketSection, pkt.transportPayloadPacketSectionSize, rec);
   } else if (pkt.destinationTransportPort == 80) {
      add_ext_http_request(pkt.transportPayloadPacketSection, pkt.transportPayloadPacketSectionSize, rec);
   }
   return 0;
}

int HTTPPlugin::pre_update(FlowRecord &rec, Packet &pkt)
{
   FlowRecordExt *ext = NULL;
   if (pkt.sourceTransportPort == 80) {
      ext = rec.getExtension(http_response);
      if(ext == NULL) {
         add_ext_http_response(pkt.transportPayloadPacketSection, pkt.transportPayloadPacketSectionSize, rec);
         return 0;
      }

      parse_http_response(pkt.transportPayloadPacketSection, pkt.transportPayloadPacketSectionSize, dynamic_cast<FlowRecordExtHTTPResp *>(ext));
   } else if (pkt.destinationTransportPort == 80) {
      ext = rec.getExtension(http_request);
      if(ext == NULL) {
         add_ext_http_request(pkt.transportPayloadPacketSection, pkt.transportPayloadPacketSectionSize, rec);
         return 0;
      }

      parse_http_request(pkt.transportPayloadPacketSection, pkt.transportPayloadPacketSectionSize, dynamic_cast<FlowRecordExtHTTPReq *>(ext));
   }
   return 0;
}

void HTTPPlugin::post_update(FlowRecord &rec, const Packet &pkt)
{
}

void HTTPPlugin::pre_export(FlowRecord &rec)
{
}

void HTTPPlugin::finish()
{
}

void HTTPPlugin::close()
{
   if (!statsout) {
      cout << "HTTP plugin stats:" << endl;
      cout << "Parsed http requests: " << requests << endl;
      cout << "Parsed http responses: " << responses << endl;
      cout << "Total http packets processed: " << total << endl;
   }
}

#define STRCPY(destination, source, begin, end)\
   len = end - (begin);\
   if (len >= (int)sizeof(destination)) {\
      len = sizeof(destination) - 1;\
   }\
   strncpy(destination, source + begin, len);\
   destination[len] = 0;

#ifdef DEBUG_HTTP
static uint32_t s_requests = 0, s_responses = 0;
#endif /* DEBUG_HTTP */

bool HTTPPlugin::parse_http_request(const char *data, int payload_len, FlowRecordExtHTTPReq *rec)
{
   total++;
#ifdef DEBUG_HTTP
   printf("---------- http parser #%u ----------\n", total);
   printf("Parsing request number: %u\n\n", ++s_requests);
   printf("Payload length: %u\n", payload_len);
#ifdef DEBUG_HTTP_PAYLOAD_PREVIEW
   printf("##################\n");
   for(int l = 0; l < payload_len; l++) {
      printf("%c", data[l]);
   }
   printf("\n##################\n");
#endif /* DEBUG_HTTP_PAYLOAD_PREVIEW */
#endif /* DEBUG_HTTP */

   if (payload_len == 0) {
#ifdef DEBUG_HTTP
      printf("Parser quits:\tpayload length = 0\n");
#endif /* DEBUG_HTTP */
      return false;
   }

   char buf[64];
   int i = strchr(data, ' ') - data, j, len = 0;
   if (i < 0 || i > 10) {
#ifdef DEBUG_HTTP
      fprintf(stderr, "Parser quits:\tnot a http request header\n");
#endif /* DEBUG_HTTP */
      return false;
   }
   j = strchr(data + i + 1, ' ') - data;
   if (j < 0) {
#ifdef DEBUG_HTTP
      fprintf(stderr, "Parser quits:\trequest is fragmented\n");
#endif /* DEBUG_HTTP */
      return false;
   }

   STRCPY(buf, data, 0, i)
   httpMethodEnum method = process_http_method(buf);
   if (method == UNDEFINED) {
#ifdef DEBUG_HTTP
      fprintf(stderr, "Parser quits:\tundefined http method: %s\n", buf);
#endif /* DEBUG_HTTP */
      return false;
   }
   rec->httpReqMethod = method;
   STRCPY(rec->httpReqUrl, data, i + 1, j)
#ifdef DEBUG_HTTP
   printf("Method: %s\n", buf);
   printf("Url: %s\n", rec->httpReqUrl);
#endif /* DEBUG_HTTP */

   i = strstr(data + j, HTTP_LINE_DELIMITER) - data + 2;
   while (i < payload_len) {
      j = strstr(data + i, HTTP_LINE_DELIMITER) - data;
      if (j < 0) {
#ifdef DEBUG_HTTP
         fprintf(stderr, "Parser quits:\theader is fragmented\n");
#endif /* DEBUG_HTTP */
         return  false;
      } else if (j == i) {
         break;
      }

      int k = strchr(data + i, HTTP_HEADER_DELIMITER) - data;
      if (k < 0) {
#ifdef DEBUG_HTTP
         fprintf(stderr, "Parser quits:\theader is fragmented\n");
#endif /* DEBUG_HTTP */
         return false;
      }
      STRCPY(buf, data, i, k)

#ifdef DEBUG_HTTP
      char debug_buff[4096];
      STRCPY(debug_buff, data, k + 2, j)
      printf("\t%s: %s\n", buf, debug_buff);
#endif /* DEBUG_HTTP */
      if (strcmp(buf, "Host") == 0) {
         STRCPY(rec->httpReqHost, data, k + 2, j)
      } else if (strcmp(buf, "User-Agent") == 0) {
         STRCPY(rec->httpReqUserAgent, data, k + 2, j)
      } else if (strcmp(buf, "Referer") == 0) {
         STRCPY(rec->httpReqReferer, data, k + 2, j)
      }
      i = j + 2;
   }

#ifdef DEBUG_HTTP
      printf("Parser quits:\tend of header section\n");
#endif /* DEBUG_HTTP */
   requests++;
   return true;
}


bool HTTPPlugin::parse_http_response(const char *data, int payload_len, FlowRecordExtHTTPResp *rec)
{
   total++;
#ifdef DEBUG_HTTP
   printf("---------- http parser #%u ----------\n", total);
   printf("Parsing response number: %u\n\n", ++s_responses);
   printf("Payload length: %u\n", payload_len);
#ifdef DEBUG_HTTP_PAYLOAD_PREVIEW
   printf("##################\n");
   for(int l = 0; l < payload_len; l++) {
      printf("%c", data[l]);
   }
   printf("\n##################\n");
#endif /* DEBUG_HTTP_PAYLOAD_PREVIEW */
#endif /* DEBUG_HTTP */

   if (payload_len == 0) {
#ifdef DEBUG_HTTP
      printf("Parser quits:\tpayload length = 0\n");
#endif /* DEBUG_HTTP */
      return false;
   }

   char buf[64];
   int i, j, len = 0;

   STRCPY(buf, data, 0, 4)
   if (strcmp(buf, "HTTP") != 0) {
#ifdef DEBUG_HTTP
      //fprintf(stderr, "Parser quits:\tpacket contains http response data\n");
#endif /* DEBUG_HTTP */
      return false;
   }

   i = strchr(data, ' ') - data;
   if (i < 0 || i > 10) {
#ifdef DEBUG_HTTP
      fprintf(stderr, "Parser quits:\tnot a http response header\n");
#endif /* DEBUG_HTTP */
      return false;
   }
   j = strchr(data + i + 1, ' ') - data;
   if (j < 0) {
#ifdef DEBUG_HTTP
      fprintf(stderr, "Parser quits:\tresponse is fragmented\n");
#endif /* DEBUG_HTTP */
      return false;
   }

   STRCPY(buf, data, i + 1, j)
   int code = atoi(buf);
   if (code <= 0 || code > 1000) {
#ifdef DEBUG_HTTP
      fprintf(stderr, "Parser quits:\twrong response code: %d\n", code);
#endif /* DEBUG_HTTP */
      return false;
   }
   rec->httpRespCode = code;
#ifdef DEBUG_HTTP
   printf("Code: %d\n", code);
#endif /* DEBUG_HTTP */

   i = strstr(data + j, HTTP_LINE_DELIMITER) - data + 2;
   while (i < payload_len) {
      j = strstr(data + i, HTTP_LINE_DELIMITER) - data;
      if (j < 0) {
#ifdef DEBUG_HTTP
         fprintf(stderr, "Parser quits:\theader is fragmented\n");
#endif /* DEBUG_HTTP */
         return  false;
      } else if (j == i) {
         break;
      }

      int k = strchr(data + i, HTTP_HEADER_DELIMITER) - data;
      if (k < 0) {
#ifdef DEBUG_HTTP
         fprintf(stderr, "Parser quits:\theader is fragmented\n");
#endif /* DEBUG_HTTP */
         return false;
      }

      STRCPY(buf, data, i, k)

#ifdef DEBUG_HTTP
      char debug_buff[4096];
      STRCPY(debug_buff, data, k + 2, j)
      printf("\t%s: %s\n", buf, debug_buff);
#endif /* DEBUG_HTTP */

      if (strcmp(buf, "Content-Type") == 0) {
         STRCPY(rec->httpRespContentType, data, k + 2, j)
      }

      i = j + 2;
   }

#ifdef DEBUG_HTTP
      printf("Parser quits:\tend of header section\n");
#endif /* DEBUG_HTTP */
   responses++;
   return true;
}

httpMethodEnum HTTPPlugin::process_http_method(const char *method) const
{
   if (strcmp(method, "GET") == 0) {
      return GET;
   } else if (strcmp(method, "HEAD") == 0) {
      return HEAD;
   } else if (strcmp(method, "POST") == 0) {
      return POST;
   } else if (strcmp(method, "PUT") == 0) {
      return PUT;
   } else if (strcmp(method, "DELETE") == 0) {
      return DELETE;
   } else if (strcmp(method, "TRACE") == 0) {
      return TRACE;
   } else if (strcmp(method, "OPTIONS") == 0) {
      return OPTIONS;
   } else if (strcmp(method, "CONNECT") == 0) {
      return CONNECT;
   } else if (strcmp(method, "PATCH") == 0) {
      return PATCH;
   }
   return UNDEFINED;
}

void HTTPPlugin::add_ext_http_request(const char *data, int payload_len, FlowRecord &rec)
{
   FlowRecordExtHTTPReq *req = new FlowRecordExtHTTPReq();
   if (!parse_http_request(data, payload_len, req)) {
      delete req;
   } else {
      rec.addExtension(req);
   }
}

void HTTPPlugin::add_ext_http_response(const char *data, int payload_len, FlowRecord &rec)
{
   FlowRecordExtHTTPResp *resp = new FlowRecordExtHTTPResp();
   if (!parse_http_response(data, payload_len, resp)) {
      delete resp;
   } else {
      rec.addExtension(resp);
   }
}

