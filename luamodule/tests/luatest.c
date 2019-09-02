/**
 * \file luatest.c
 * \brief Application for LUA script testing.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2019
 */
/*
 * Copyright (C) 2019 CESNET
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
#include <stdio.h>
#include <unirec/unirec.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "luatest.h"
#include "fields.h"

#define BASIC_FLOW_TEMPLATE "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,DIR_BIT_FIELD,TOS,TTL,SRC_MAC,DST_MAC,LINK_BIT_FIELD"

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint8 TOS,
   uint8 TTL,
   macaddr SRC_MAC,
   macaddr DST_MAC
)

ur_template_t *tmplt_in = NULL;
ur_template_t *tmplt_out = NULL;
const void *rec_in = NULL;
void *rec_in_test = NULL;
void *rec_out = NULL;
module_state_t module_state = STATE_INIT;

int create_records(ur_template_t **t_in,  void **r_in,
                   ur_template_t **t_out, void **r_out, const char *spec)
{
   /* Create templates based on IFC spec. */
   *t_in = ur_create_template(spec, NULL);
   *t_out = ur_create_template(spec, NULL);
   if (*t_in == NULL || *t_out == NULL) {
      fprintf(stderr, "Error: templates could not be created\n");
      return 1;
   }

   /* Create records based on IFC spec. */
   *r_in  = ur_create_record(*t_in, UR_MAX_SIZE);
   *r_out = ur_create_record(*t_out, UR_MAX_SIZE);
   if (*r_in == NULL || *r_out == NULL) {
      fprintf(stderr, "Error: records could not be created\n");
      return 1;
   }

   return 0;
}

void fill_sample_record(ur_template_t *tmplt, void *rec)
{
   ip_addr_t src_ip; ip_from_str("192.168.2.1", &src_ip);
   ip_addr_t dst_ip; ip_from_str("77.147.32.88", &dst_ip);
   ur_time_t time_first = ur_time_from_sec_msec(1565886990, 12);
   ur_time_t time_last  = ur_time_from_sec_msec(1565886993, 602);
   int link_bit_field = 1;
   int dir_bit_field = 0;
   int ip_proto = 6;
   int src_port = 33624;
   int dst_port = 80;
   int pkt_total_cnt = 19;
   int octet_total_length = 12653;
   int tcp_control_bits = 25;
   int ip_tos = 0;
   int ip_ttl = 118;
   mac_addr_t src_mac = mac_from_bytes((uint8_t []) {0x11, 0x11, 0x11, 0x11, 0x11, 0x11});
   mac_addr_t dst_mac = mac_from_bytes((uint8_t []) {0x22, 0x22, 0x22, 0x22, 0x22, 0x22});

   ur_set(tmplt, rec, F_SRC_IP, src_ip);
   ur_set(tmplt, rec, F_DST_IP, dst_ip);
   ur_set(tmplt, rec, F_TIME_FIRST, time_first);
   ur_set(tmplt, rec, F_TIME_LAST, time_last);
   ur_set(tmplt, rec, F_LINK_BIT_FIELD, link_bit_field);
   ur_set(tmplt, rec, F_DIR_BIT_FIELD, dir_bit_field);
   ur_set(tmplt, rec, F_PROTOCOL, ip_proto);
   ur_set(tmplt, rec, F_SRC_PORT, src_port);
   ur_set(tmplt, rec, F_DST_PORT, dst_port);
   ur_set(tmplt, rec, F_PACKETS, pkt_total_cnt);
   ur_set(tmplt, rec, F_BYTES, octet_total_length);
   ur_set(tmplt, rec, F_TCP_FLAGS, tcp_control_bits);
   ur_set(tmplt, rec, F_TOS, ip_tos);
   ur_set(tmplt, rec, F_TTL, ip_ttl);
   ur_set(tmplt, rec, F_DST_MAC, dst_mac);
   ur_set(tmplt, rec, F_SRC_MAC, src_mac);
}

int switch_templates(lua_State *luaVM)
{
   void *rec_tmp = rec_in_test;
   rec_in_test = rec_out;
   rec_out = rec_tmp;
   rec_in = rec_in_test;

   ur_template_t *tmplt_tmp = tmplt_in;
   tmplt_in = tmplt_out;
   tmplt_out = tmplt_tmp;

   return 0;
}

int main(int argc, char *argv[])
{
   lua_State *luaVM;
   const char *spec = BASIC_FLOW_TEMPLATE;

   if (argc != 2) {
      fprintf(stderr, "Error: lua script path not specified\n");
      return 1;
   }

   /* Create templates and records. */
   if (create_records(&tmplt_in, &rec_in_test, &tmplt_out, &rec_out, spec)) {
      fprintf(stderr, "Error: input and output templates failed to create\n");
      return 1;
   }
   fill_sample_record(tmplt_in, rec_in_test);
   rec_in = rec_in_test;

   /* Create LUA context. */
   luaVM = create_lua_context(argv[1]);
   if (luaVM == NULL) {
      return 1;
   }
   lua_register(luaVM, "ur_switch", switch_templates);

   /* Call template recv LUA function. */
   module_state = STATE_TEMPLATE_RECV;
   lua_getglobal(luaVM, ON_TEMPLATE_RECV_NAME);
   lua_call(luaVM, 0, 0);

   ur_copy_fields(tmplt_out, rec_out, tmplt_in, rec_in);

   /* Call record recv LUA function. */
   module_state = STATE_RECORD_RECV;
   lua_getglobal(luaVM, ON_RECORD_RECV_NAME);
   lua_call(luaVM, 0, 0);

   ur_free_template(tmplt_in);
   ur_free_template(tmplt_out);
   ur_free_record(rec_in_test);
   ur_free_record(rec_out);
   ur_finalize();
   lua_close(luaVM);
   return 0;
}
