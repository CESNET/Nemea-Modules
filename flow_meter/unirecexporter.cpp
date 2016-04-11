/**
 * \file unirecexporter.cpp
 * \brief Flow exporter converting flows to UniRec and sending them to TRAP ifc
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2014-2015 CESNET
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

#include <string>
#include <vector>
#include <algorithm>
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
UnirecExporter::UnirecExporter() : out_ifc_cnt(0), tmplt(NULL), record(NULL)
{
}

/**
 * \brief Initialize exporter.
 * \param [in] plugins Active plugins.
 * \param [in] ifc_cnt Output interface count.
 * \param [in] basic_ifc_num Basic output interface number.
 * \return 0 on success or negative value when error occur.
 */
int UnirecExporter::init(const vector<FlowCachePlugin *> &plugins, int ifc_cnt, int basic_ifc_number)
{
   string template_str(BASIC_UNIREC_TEMPLATE);
   out_ifc_cnt = ifc_cnt;
   basic_ifc_num = basic_ifc_number;
   ifc_mapping.clear();

   tmplt = new ur_template_t*[out_ifc_cnt];
   record = new void*[out_ifc_cnt];

   for (int i = 0; i < out_ifc_cnt; i++) {
      tmplt[i] = NULL;
      record[i] = NULL;
   }

   char *error = NULL;
   if (basic_ifc_num >= 0) {
      tmplt[basic_ifc_num] = ur_create_output_template(basic_ifc_num, template_str.c_str(), &error);
      if (tmplt[basic_ifc_num] == NULL) {
         fprintf(stderr, "UnirecExporter: %s\n", error);
         free(error);
         free_unirec_resources();
         return -2;
      }

      record[basic_ifc_num] = ur_create_record(tmplt[basic_ifc_num], UR_MAX_SIZE);
      if (record[basic_ifc_num] == NULL) {
         free_unirec_resources();
         return -3;
      }
   }

   for (unsigned int i = 0; i < plugins.size(); i++) {
      FlowCachePlugin * const tmp = plugins[i];
      vector<plugin_opt> &opts = tmp->get_options();
      int ifc = -1;

      for (unsigned int j = 0; j < opts.size(); j++) { // Create plugin extension id -> output interface mapping.
         ifc_mapping[opts[j].ext_type] = opts[j].out_ifc_num;
         ifc = opts[j].out_ifc_num;
      }

      if (opts.size() == 0 || ifc < 0) {
         continue;
      }

      // Create unirec templates.
      tmplt[ifc] = ur_create_output_template(ifc, (template_str + string(",") + tmp->get_unirec_field_string()).c_str(), &error);
      if (tmplt == NULL) {
         fprintf(stderr, "UnirecExporter: %s\n", error);
         free(error);
         free_unirec_resources();
         return -2;
      }
   }

   for (int i = 0; i < out_ifc_cnt; i++) { // Create unirec records.
      if (tmplt[i] != NULL) {
         record[i] = ur_create_record(tmplt[i], UR_MAX_SIZE);

         if (record == NULL) {
            free_unirec_resources();
            return -3;
         }
      }
   }

   return 0;
}

/**
 * \brief Close connection and free resources.
 */
void UnirecExporter::close()
{
   for (int i = 0; i < out_ifc_cnt; i++) {
      trap_send(i, "", 1);
   }
   trap_finalize();

   free_unirec_resources();

   basic_ifc_num = -1;
   out_ifc_cnt = 0;
}

/**
 * \brief Free unirec templates and unirec records.
 */
void UnirecExporter::free_unirec_resources()
{
   if (tmplt) {
      for (int i = 0; i < out_ifc_cnt; i++) {
         if (tmplt[i] != NULL) {
            ur_free_template(tmplt[i]);
         }
      }
      delete [] tmplt;
      tmplt = NULL;
   }
   if (record) {
      for (int i = 0; i < out_ifc_cnt; i++) {
         if (record[i] != NULL) {
            ur_free_record(record[i]);
         }
      }
      delete [] record;
      record = NULL;
   }
}

int UnirecExporter::export_flow(FlowRecord &flow)
{
   FlowRecordExt *ext = flow.exts;
   vector<int> to_export; // Contains output ifc numbers.
   ur_template_t *tmplt_ptr = NULL;
   void *record_ptr = NULL;

   for (int i = 0; i < out_ifc_cnt; i++) {
      ur_clear_varlen(tmplt[i], record[i]);
      memset(record[i], 0, ur_rec_fixlen_size(tmplt[i]));
   }

   if (basic_ifc_num >= 0 && ext == NULL) { // Process basic flow.
      tmplt_ptr = tmplt[basic_ifc_num];
      record_ptr = record[basic_ifc_num];

      ur_clear_varlen(tmplt_ptr, record_ptr);
      fill_basic_flow(flow, tmplt_ptr, record_ptr);
      trap_send(basic_ifc_num, record_ptr, ur_rec_fixlen_size(tmplt_ptr) + ur_rec_varlen_size(tmplt_ptr, record_ptr));
      return 0;
   }

   while (ext != NULL) {
      map<int, int>::iterator it = ifc_mapping.find(ext->extType); // Find if mapping exists.
      if (it != ifc_mapping.end()) {
         int ifc_num = it->second;
         if (ifc_num < 0) {
            ext = ext->next;
            continue;
         }

         tmplt_ptr = tmplt[ifc_num];
         record_ptr = record[ifc_num];
         if (find(to_export.begin(), to_export.end(), ifc_num) == to_export.end()) {
            to_export.push_back(ifc_num);
         }

         fill_basic_flow(flow, tmplt_ptr, record_ptr);
         ext->fillUnirec(tmplt_ptr, record_ptr); /* Add each extension header into unirec record. */
      }
      ext = ext->next;
   }

   for (unsigned int i = 0; i < to_export.size(); i++) {
      tmplt_ptr = tmplt[to_export[i]];
      record_ptr = record[to_export[i]];
      trap_send(to_export[i], record_ptr, ur_rec_fixlen_size(tmplt_ptr) + ur_rec_varlen_size(tmplt_ptr, record_ptr));
   }

   return 0;
}

/**
 * \brief Fill record with basic flow fields.
 * \param [in] flow Flow record.
 * \param [in] tmplt_ptr Pointer to unirec template.
 * \param [out] record_ptr Pointer to unirec record.
 */
void UnirecExporter::fill_basic_flow(FlowRecord &flow, ur_template_t *tmplt_ptr, void *record_ptr)
{
   uint64_t tmp_time;
   uint32_t time_sec;
   uint32_t time_msec;

   if (flow.ipVersion == 4) {
      ur_set(tmplt_ptr, record_ptr, F_SRC_IP, ip_from_4_bytes_le((char *)&flow.sourceIPv4Address));
      ur_set(tmplt_ptr, record_ptr, F_DST_IP, ip_from_4_bytes_le((char *)&flow.destinationIPv4Address));
   } else {
      ur_set(tmplt_ptr, record_ptr, F_SRC_IP, ip_from_16_bytes_le((char *)&flow.sourceIPv6Address));
      ur_set(tmplt_ptr, record_ptr, F_DST_IP, ip_from_16_bytes_le((char *)&flow.destinationIPv6Address));
   }

   time_sec = (uint32_t)flow.flowStartTimestamp;
   time_msec = (uint32_t)((flow.flowStartTimestamp - ((double)((uint32_t)flow.flowStartTimestamp))) * 1000);
   tmp_time = ur_time_from_sec_msec(time_sec, time_msec);
   ur_set(tmplt_ptr, record_ptr, F_TIME_FIRST, tmp_time);

   time_sec = (uint32_t)flow.flowEndTimestamp;
   time_msec = (uint32_t)((flow.flowEndTimestamp - ((double)((uint32_t)flow.flowEndTimestamp))) * 1000);
   tmp_time = ur_time_from_sec_msec(time_sec, time_msec);
   ur_set(tmplt_ptr, record_ptr, F_TIME_LAST, tmp_time);

   ur_set(tmplt_ptr, record_ptr, F_PROTOCOL, flow.protocolIdentifier);
   ur_set(tmplt_ptr, record_ptr, F_SRC_PORT, flow.sourceTransportPort);
   ur_set(tmplt_ptr, record_ptr, F_DST_PORT, flow.destinationTransportPort);
   ur_set(tmplt_ptr, record_ptr, F_PACKETS, flow.packetTotalCount);
   ur_set(tmplt_ptr, record_ptr, F_BYTES, flow.octetTotalLength);
   ur_set(tmplt_ptr, record_ptr, F_TCP_FLAGS, flow.tcpControlBits);

   ur_set(tmplt_ptr, record_ptr, F_DIR_BIT_FIELD, 0);
   ur_set(tmplt_ptr, record_ptr, F_LINK_BIT_FIELD, 0);
}

