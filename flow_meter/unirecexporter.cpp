/**
 * \file unirecexporter.cpp
 */

#include <string>
#include <vector>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "unirecexporter.h"
#include "fields.h"
#include "flowexporter.h"
#include "flowifc.h"
#include "flow_meter.h"

using namespace std;

#define BASIC_UNIREC_TEMPLATE "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL"

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
int UnirecExporter::init(const std::vector<FlowCachePlugin *> &plugins)
{
   std::string template_str(BASIC_UNIREC_TEMPLATE);

   template_str += generate_ext_template(plugins);

   char *error = NULL;
   tmplt = ur_create_output_template(0, template_str.c_str(), &error);
   if (tmplt == NULL) {
      fprintf(stderr, "UnirecExporter: %s\n", error);
      free(error);
      return -2;
   }

   record = ur_create_record(tmplt, plugins.size() != 0 ? UR_MAX_SIZE : 0);
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
   ur_clear_varlen(tmplt, record);

   while (ext != NULL) {
      ext->fillUnirec(tmplt, record); /* Add each extension header into unirec record. */
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

   return 0;
}

/**
 * \brief Create extension template from active plugins.
 * \param [in] plugins Active plugins.
 * \return String with generated template.
 */
std::string UnirecExporter::generate_ext_template(const std::vector<FlowCachePlugin *> &plugins) const
{
   std::string template_str("");
   for (unsigned int i = 0; i < plugins.size(); i++) {
      std::string tmp = plugins[i]->get_unirec_field_string();
      if (tmp != "") {
         template_str += "," + tmp;
      }
   }
   return template_str;
}
