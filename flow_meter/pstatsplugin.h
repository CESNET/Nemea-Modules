/**
 * \file pstatsplugin.h
 * \brief Plugin for parsing pstats traffic.
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@cesnet.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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
 * This software is provided as is'', and any express or implied
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

#ifndef PSTATSPLUGIN_H
#define PSTATSPLUGIN_H

#include <string>

#include "fields.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

#ifndef PSTATS_MAXELEMCOUNT
#define PSTATS_MAXELEMCOUNT 20
#endif

using namespace std;

#define IPFIX_TLS_RECORD_LENGTHS 44956
#define IPFIX_TLS_RECORD_TIMES 44957

/**
 * \brief Flow record extension header for storing parsed PSTATS packets.
 */
struct RecordExtPSTATS : RecordExt {
   uint16_t pkt_sizes[PSTATS_MAXELEMCOUNT];
   uint32_t pkt_delays[PSTATS_MAXELEMCOUNT];
   uint8_t pkt_tcp_flgs[PSTATS_MAXELEMCOUNT];
   struct timeval pkt_timestamps[PSTATS_MAXELEMCOUNT];
   uint8_t pkt_count;

   typedef enum eHdrFieldID
   {
     PktSize = 44956,
     PktDelays = 44957,
     PktFlags = 44964,
     PktDir = 44964,
     PktTmstp = 44966
   }eHdrSemantic;


   struct IpfixBasicRecordListHdr{
     IpfixBasicRecordListHdr(uint8_t flag, uint16_t length, uint8_t hdrSemantic,
                          eHdrFieldID hdrFieldID, uint16_t hdrElementLength,
                          uint32_t hdrEnterpriseNum):flag(flag),
                          length(length),hdrSemantic(hdrSemantic),
                          hdrFieldID(hdrFieldID),
                          hdrElementLength(hdrElementLength),
                          hdrEnterpriseNum(hdrEnterpriseNum){};
    uint8_t flag;
    uint16_t length;
    uint8_t hdrSemantic;
    uint16_t hdrFieldID;
    uint16_t hdrElementLength;
    uint32_t hdrEnterpriseNum;
   };

   static const uint8_t IpfixBasicListRecordHdrSize = 12;
   static const uint8_t IpfixBasicListHdrSize = 9;
   static const uint32_t CesnetPem = 8057;



   int32_t FillBasicListBuffer(RecordExtPSTATS::IpfixBasicRecordListHdr& IpfixBasicListRecord, uint8_t * buffer, int size)
   {
     uint32_t bufferPtr = 0;
      //Copy flag
     buffer[bufferPtr] = IpfixBasicListRecord.flag;
     bufferPtr+=sizeof(uint8_t);
     //Copy length;
     *(reinterpret_cast<uint16_t*>(buffer + bufferPtr)) = htons(IpfixBasicListRecord.length);
     bufferPtr+=sizeof(uint16_t);
     //copy hdr_semantic
     buffer[bufferPtr] = IpfixBasicListRecord.hdrSemantic;
     bufferPtr+=sizeof(uint8_t);
     //copy hdr_field_id
     *(reinterpret_cast<uint16_t*>(buffer + bufferPtr)) = htons(IpfixBasicListRecord.hdrFieldID);
     bufferPtr+=sizeof(uint16_t);

     *(reinterpret_cast<uint16_t*>(buffer + bufferPtr)) = htons(IpfixBasicListRecord.hdrElementLength);
     bufferPtr+=sizeof(uint16_t);

     *(reinterpret_cast<uint32_t*>(buffer + bufferPtr)) = htonl(IpfixBasicListRecord.hdrEnterpriseNum);
     bufferPtr+=sizeof(uint32_t);

     return bufferPtr;
   }

   RecordExtPSTATS() : RecordExt(pstats)
   {
      memset(pkt_sizes, 0, PSTATS_MAXELEMCOUNT * sizeof(pkt_sizes[0]));
      memset(pkt_delays, 0, PSTATS_MAXELEMCOUNT * sizeof(pkt_delays[0]));
      memset(pkt_timestamps, 0, PSTATS_MAXELEMCOUNT * sizeof(pkt_timestamps[0]));
      memset(pkt_tcp_flgs, 0, PSTATS_MAXELEMCOUNT * sizeof(pkt_tcp_flgs[0]));
      pkt_count = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
#ifndef DISABLE_UNIREC
      ur_array_resize(tmplt, record, F_STATS_PCKT_TIMESTAMPS, pkt_count);
      ur_array_resize(tmplt, record, F_STATS_PCKT_DELAYS, pkt_count);
      ur_array_resize(tmplt, record, F_STATS_PCKT_SIZES, pkt_count);
      ur_array_resize(tmplt, record, F_STATS_PCKT_TCPFLGS, pkt_count);
      for (uint8_t i = 0; i < pkt_count; i++) {
         ur_time_t ts = ur_time_from_sec_usec(pkt_timestamps[i].tv_sec, pkt_timestamps[i].tv_usec);
         ur_array_set(tmplt, record, F_STATS_PCKT_TIMESTAMPS, i, ts);
         ur_array_set(tmplt, record, F_STATS_PCKT_DELAYS, i, pkt_delays[i]);
         ur_array_set(tmplt, record, F_STATS_PCKT_SIZES, i, pkt_sizes[i]);
         ur_array_set(tmplt, record, F_STATS_PCKT_TCPFLGS, i, pkt_tcp_flgs[i]);
      }
#endif
   }

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int32_t bufferPtr;
      RecordExtPSTATS::IpfixBasicRecordListHdr hdr(255,//Maximum size see rfc631
                                          IpfixBasicListHdrSize + pkt_count*(sizeof(uint16_t)),
                                          3,
                                          PktSize,
                                          sizeof(uint16_t),
                                          CesnetPem);
      //Check sufficient size of buffer
      if(3*IpfixBasicListRecordHdrSize + pkt_count*(sizeof(uint16_t)) + 3*pkt_count*(sizeof(uint32_t))  > size)
        {
          return -1;
        }

      //fill buffer with basic list header and packet sizes
      bufferPtr = FillBasicListBuffer(hdr, buffer, size);
      for(int i = 0; i< pkt_count; i++)
      {
        (*reinterpret_cast<uint16_t *>(buffer + bufferPtr)) = htons(pkt_sizes[i]);
        bufferPtr+=sizeof(uint16_t);
      }

      //update information in hdr for next basic list with packet delays
      hdr.length = IpfixBasicListHdrSize + pkt_count*(sizeof(uint32_t));
      hdr.hdrFieldID = PktDelays;
      hdr.hdrElementLength = sizeof(uint32_t);

      bufferPtr += FillBasicListBuffer(hdr, buffer + bufferPtr, size);
      for(int i = 0; i< pkt_count; i++)
      {
        (*reinterpret_cast<uint32_t *>(buffer + bufferPtr)) = htonl(pkt_delays[i]);
        bufferPtr+=sizeof(uint32_t);
      }

      //update information in hdr for next basic list with packet timestamps
      //timestamps are in format [i] = sec, [i+1] = usec
      hdr.length = IpfixBasicListHdrSize + pkt_count*2*(sizeof(uint32_t));
      hdr.hdrFieldID = PktTmstp;
      bufferPtr += FillBasicListBuffer(hdr, buffer + bufferPtr, size);
      for(int i = 0; i<pkt_count; i++)
      {
        (*reinterpret_cast<uint32_t *>(buffer + bufferPtr)) = htonl(pkt_timestamps[i].tv_sec);
        bufferPtr+=sizeof(uint32_t);
        (*reinterpret_cast<uint32_t *>(buffer + bufferPtr)) = htonl(pkt_timestamps[i].tv_usec);
        bufferPtr+=sizeof(uint32_t);
      }

      //
      hdr.length = IpfixBasicListHdrSize + pkt_count*(sizeof(uint8_t));
      hdr.hdrFieldID = PktFlags;
      hdr.hdrElementLength = sizeof(uint8_t);

      bufferPtr += FillBasicListBuffer(hdr, buffer + bufferPtr, size);
      memcpy(buffer + bufferPtr, pkt_tcp_flgs, pkt_count);
      bufferPtr+=pkt_count;

      return bufferPtr;
   }
};

/**
 * \brief Flow cache plugin for parsing PSTATS packets.
 */
class PSTATSPlugin : public FlowCachePlugin
{
public:
   PSTATSPlugin(const options_t &module_options);
   PSTATSPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void update_record(RecordExtPSTATS *pstats_data, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
};

#endif