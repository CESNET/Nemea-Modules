/**
 * \file VPNDetectorPlugin.cpp
 * \brief Plugin for parsing vpndetector traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \author Martin Ctrnacty <ctrnama2@fit.cvut.cz>
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

#include <iostream>

#include "vpndetectorplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"
#include "ipfix-elements.h"

using namespace std;

#define VPNDETECTOR_UNIREC_TEMPLATE "VPN_CONF_LEVEL"

UR_FIELDS (
   uint8 VPN_CONF_LEVEL
)

VPNDetectorPlugin::VPNDetectorPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

VPNDetectorPlugin::VPNDetectorPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

void VPNDetectorPlugin::update_record(RecordExtVPNDetector* vpn_data, const Packet &pkt)
{
  uint8_t opcode = 0;
  uint8_t opcodeindex = 0;
  switch(static_cast<e_ip_proto_nbr>(pkt.ip_proto))
  {
    case udp:
      if (pkt.payload_length == 0)
        return;
      opcodeindex = c_udp_opcode_index;
      opcode = (pkt.payload[opcodeindex] >> 3);
    break;
    case tcp:
      if (pkt.payload_length < c_tcp_opcode_index)
        return;
      opcodeindex = c_tcp_opcode_index;
      opcode = (pkt.payload[opcodeindex] >> 3);
    break;
  }

  switch(opcode)
  {
    //p_control_hard_reset_client
    case p_control_hard_reset_client_v1:
    case p_control_hard_reset_client_v2:
    case p_control_hard_reset_client_v3:
      vpn_data->status = status_reset_client; //client to server
      vpn_data->invalid_pkt_cnt = -1;
      vpn_data->client_ip = pkt.src_ip;
      break;

    //p_control_hard_reset_server
    case p_control_hard_reset_server_v1:
    case p_control_hard_reset_server_v2:
      if (vpn_data->status == status_reset_client && compare_ip(vpn_data->client_ip, pkt.dst_ip, pkt.ip_version)) { //server to client
        vpn_data->status = status_reset_server;
        vpn_data->invalid_pkt_cnt = -1;
      }
      else {
        vpn_data->invalid_pkt_cnt++;
        if (vpn_data->invalid_pkt_cnt == invalid_pckt_treshold) vpn_data->status = status_null;
      }
      break;

    //p_control_soft_reset
    case p_control_soft_reset_v1:
      break;

    //p_control
    case p_control_v1:
      if (vpn_data->status == status_ack && compare_ip(vpn_data->client_ip, pkt.src_ip, pkt.ip_version) && check_ssl_client_hello(pkt, opcodeindex)) { //client to server
        vpn_data->status = status_client_hello;
        vpn_data->invalid_pkt_cnt = -1;
      } else if (vpn_data->status == status_client_hello && compare_ip(vpn_data->client_ip, pkt.dst_ip, pkt.ip_version) && check_ssl_server_hello(pkt, opcodeindex)) { //server to client
        vpn_data->status = status_server_hello;
        vpn_data->invalid_pkt_cnt = -1;
      } else if (vpn_data->status == status_server_hello || vpn_data->status == status_control_ack) {
        vpn_data->status = status_control_ack;
        vpn_data->invalid_pkt_cnt = -1;
      } else {
        vpn_data->invalid_pkt_cnt++;
        if (vpn_data->invalid_pkt_cnt == invalid_pckt_treshold) vpn_data->status = status_null;
      }
      break;

    //p_ack
    case p_ack_v1:
      if (vpn_data->status == status_reset_server && compare_ip(vpn_data->client_ip, pkt.src_ip, pkt.ip_version)) { //client to server
        vpn_data->status = status_ack;
        vpn_data->invalid_pkt_cnt = -1;
      }
      else if (vpn_data->status == status_server_hello || vpn_data->status == status_control_ack) {
        vpn_data->status = status_control_ack;
        vpn_data->invalid_pkt_cnt = -1;
      }
      break;

    //p_data
    case p_data_v1:
    case p_data_v2:
      if (vpn_data->status == status_control_ack || vpn_data->status == status_data) {
        vpn_data->status = status_data;
        vpn_data->invalid_pkt_cnt = -1;
      }
      vpn_data->data_pkt_cnt++;
      break;

    //no opcode
    default:
      break;
  }

  vpn_data->pkt_cnt++;

  //packets that did not make a valid transition
  if (vpn_data->invalid_pkt_cnt >= invalid_pckt_treshold) {
    vpn_data->status = status_null;
    vpn_data->invalid_pkt_cnt = -1;
  }
  vpn_data->invalid_pkt_cnt++;
  return;
}

int VPNDetectorPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtVPNDetector *vpn_data = new RecordExtVPNDetector();
   rec.addExtension(vpn_data);

   update_record(vpn_data, pkt);
   return 0;
}

int VPNDetectorPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtVPNDetector *vpn_data = (RecordExtVPNDetector *) rec.getExtension(vpndetector);
   update_record(vpn_data, pkt);
   return 0;
}

void VPNDetectorPlugin::pre_export(Flow &rec)
{
  RecordExtVPNDetector *vpn_data = (RecordExtVPNDetector *) rec.getExtension(vpndetector);
  if (vpn_data->pkt_cnt > min_pckt_treshold && vpn_data->status == status_data)
     vpn_data->possible_vpn = 100;
  else if (vpn_data->pkt_cnt > min_pckt_treshold && (vpn_data->data_pkt_cnt / vpn_data->pkt_cnt) >= data_pckt_treshold)
     vpn_data->possible_vpn = vpn_data->data_pkt_cnt / vpn_data->pkt_cnt;
    return;
}

const char *ipfix_template[] = {
   IPFIX_VPNDETECTOR_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **VPNDetectorPlugin::get_ipfix_string()
{
   return ipfix_template;
}

string VPNDetectorPlugin::get_unirec_field_string()
{
   return VPNDETECTOR_UNIREC_TEMPLATE;
}

bool VPNDetectorPlugin::compare_ip(ipaddr_t ip_1, ipaddr_t ip_2, uint8_t ip_version)
{
  if (ip_version == 4 && !memcmp(&ip_1, &ip_2, 4))
    return 1;
  if (ip_version == 6 && !memcmp(&ip_1, &ip_2, 16))
    return 1;
  return 0;
}

bool VPNDetectorPlugin::check_ssl_client_hello(const Packet &pkt, uint8_t opcodeindex)
{
  if (pkt.payload_length > opcodeindex + 19 && pkt.payload[opcodeindex + 14] == 0x16 && pkt.payload[opcodeindex + 19] == 0x01)
    return 1;
  if (pkt.payload_length > opcodeindex + 47 && pkt.payload[opcodeindex + 42] == 0x16 && pkt.payload[opcodeindex + 47] == 0x01)
    return 1;
  return 0;
}

bool VPNDetectorPlugin::check_ssl_server_hello(const Packet &pkt, uint8_t opcodeindex)
{
  if (pkt.payload_length > opcodeindex + 31 && pkt.payload[opcodeindex + 26] == 0x16 && pkt.payload[opcodeindex + 31] == 0x02)
    return 1;
  if (pkt.payload_length > opcodeindex + 59 && pkt.payload[opcodeindex + 54] == 0x16 && pkt.payload[opcodeindex + 59] == 0x02)
    return 1;
  return 0;
}
