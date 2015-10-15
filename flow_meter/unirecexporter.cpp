/**
 * \file unirecexporter.cpp
 */

#include <string>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "unirecexporter.h"
#include "fields.h"
#include "flowexporter.h"
#include "flowifc.h"
#include "flow_meter.h"

#include "httpplugin.h"
//#include "dnsplugin.h"

using namespace std;

/**
 * \brief Constructor.
 */
UnirecExporter::UnirecExporter() : tmplt(NULL), record(NULL)
{
}

/**
 * \brief Initialize exporter.
 * \param [in] plugins Active plugins.
 * \return 0 on success, non 0 when error occur.
 */
int UnirecExporter::init(const uint32_t &plugins)
{
   std::string template_str("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL");

   template_str += generate_ext_template(plugins);

   char *error = NULL;
   tmplt = ur_create_output_template(0, template_str.c_str(), &error);
   if (tmplt == NULL) {
      fprintf(stderr, "UnirecExporter: %s\n", error);
      free(error);
      return -2;
   }

   record = ur_create_record(tmplt, plugins & 0xFF ? UR_MAX_SIZE : 0);
   if (record == NULL) {
      ur_free_template(tmplt);
      return -3;
   }

   return 0;
}

/**
 * \brief Close connection and free resources.
 */
void UnirecExporter::close()
{
   trap_send(0, "", 1);
   trap_finalize();

   ur_free_template(tmplt);
   ur_free_record(record);
}

int UnirecExporter::export_flow(FlowRecord &flow)
{

   FlowRecordExt *ext = flow.exts;
   do {
      ur_clear_varlen(tmplt, record);

      if (ext != NULL) {
         uint16_t ext_type = ext->extType;

         if (ext_type == http_response) {
            FlowRecordExtHTTPResp *tmp = dynamic_cast<FlowRecordExtHTTPResp *>(ext);

            ur_set(tmplt, record, F_HTTP_RESPONSE_CODE, tmp->httpRespCode);
            ur_set_string(tmplt, record, F_HTTP_CONTENT_TYPE, tmp->httpRespContentType);

         } else if (ext_type == http_request) {
            FlowRecordExtHTTPReq *tmp = dynamic_cast<FlowRecordExtHTTPReq *>(ext);

            ur_set_string(tmplt, record, F_HTTP_METHOD, tmp->httpReqMethod);
            ur_set_string(tmplt, record, F_HTTP_HOST, tmp->httpReqHost);
            ur_set_string(tmplt, record, F_HTTP_URL, tmp->httpReqUrl);
            ur_set_string(tmplt, record, F_HTTP_USER_AGENT, tmp->httpReqUserAgent);
            ur_set_string(tmplt, record, F_HTTP_REFERER, tmp->httpReqReferer);

         } /*else if (ext_type == dns) {
            FlowRecordExtDNS *tmp = dynamic_cast<FlowRecordExtDNS *>(ext);

            ur_set(tmplt, record, F_DNS_QTYPE, tmp->dns_qtype);
            //ur_set_var(tmplt, record, F_DNS_NAME, tmp->dns_name, );
            //ur_set_var(tmplt, record, F_DNS_RDATA, tmp->dns_rdata, );
         }*/
         ext = ext->next;
      }

      uint64_t tmp_time;
      uint32_t time_sec;
      uint32_t time_msec;

      if (flow.ipVersion == 4) {
         ur_set(tmplt, record, F_SRC_IP, ip_from_4_bytes_le((char *)&flow.sourceIPv4Address));
         ur_set(tmplt, record, F_DST_IP, ip_from_4_bytes_le((char *)&flow.destinationIPv4Address));
      } else {
         ur_set(tmplt, record, F_SRC_IP, ip_from_16_bytes_le((char *)&flow.sourceIPv6Address));
         ur_set(tmplt, record, F_DST_IP, ip_from_16_bytes_le((char *)&flow.destinationIPv6Address));
      }

      time_sec = (uint32_t)flow.flowStartTimestamp;
      time_msec = (uint32_t)((flow.flowStartTimestamp - ((double)((uint32_t)flow.flowStartTimestamp))) * 1000);
      tmp_time = ur_time_from_sec_msec(time_sec, time_msec);
      ur_set(tmplt, record, F_TIME_FIRST, tmp_time);

      time_sec = (uint32_t)flow.flowEndTimestamp;
      time_msec = (uint32_t)((flow.flowEndTimestamp - ((double)((uint32_t)flow.flowEndTimestamp))) * 1000);
      tmp_time = ur_time_from_sec_msec(time_sec, time_msec);
      ur_set(tmplt, record, F_TIME_LAST, tmp_time);

      ur_set(tmplt, record, F_PROTOCOL, flow.protocolIdentifier);
      ur_set(tmplt, record, F_SRC_PORT, flow.sourceTransportPort);
      ur_set(tmplt, record, F_DST_PORT, flow.destinationTransportPort);
      ur_set(tmplt, record, F_PACKETS, flow.packetTotalCount);
      ur_set(tmplt, record, F_BYTES, flow.octetTotalLength);
      ur_set(tmplt, record, F_TCP_FLAGS, flow.tcpControlBits);

      ur_set(tmplt, record, F_DIR_BIT_FIELD, 0);
      ur_set(tmplt, record, F_LINK_BIT_FIELD, 0);

      trap_send(0, record, ur_rec_fixlen_size(tmplt) + ur_rec_varlen_size(tmplt, record));
   } while (ext != NULL);

   return 0;
}

/**
 * \brief Create extension template.
 * \param [in] plugins Active plugins.
 * \return String with generated template.
 */
std::string UnirecExporter::generate_ext_template(const uint32_t &plugins)
{
   std::string template_str("");
   if (plugins & PLUGIN_HTTP) {
      template_str += ",HTTP_METHOD,HTTP_HOST,HTTP_URL,HTTP_USER_AGENT,HTTP_REFERER,HTTP_RESPONSE_CODE,HTTP_CONTENT_TYPE";
   } else if (plugins & PLUGIN_DNS) {
      template_str += ",DNS_QTYPE,DNS_NAME,DNS_RDATA";
   }

   return template_str;
}
