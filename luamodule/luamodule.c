/**
 * \file luamodule.c
 * \brief Test module for unirec record manipulation using LUA script.
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

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <ctype.h>
#include <math.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "luamodule.h"
#include "luafuncs.h"
#include "luahelper.h"
#include "template.h"

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("luamodule", "Manipulate with unirec record using LUA script.", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('n', "no_eof", "Don't forward EOF message.", no_argument, "none") \
  PARAM('l', "lua", "Path to lua script.", required_argument, "string")

static int stop = 0;
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

ur_template_t *tmplt_in = NULL;
ur_template_t *tmplt_out = NULL;
const void *rec_in = NULL;
void *rec_out = NULL;
module_state_t module_state = STATE_INIT;
int drop_message = 0;

int main(int argc, char *argv[])
{
   uint8_t data_fmt = TRAP_FMT_UNKNOWN;
   uint16_t rec_size = 0;
   int ret;
   int module_status = 0;
   int eof = 1; /* eof - send EOF message on exit. */
   long long record_count = 0;
   const char *script_path = NULL;
   lua_State *luaVM = NULL;

   /* TRAP initialization. */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info)
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   /* Unset data format on input and output interface. */
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, NULL);

   /* Parse parameters. */
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'n':
         eof = 0;
         break;
      case 'l':
         script_path = optarg;
         break;
      default:
         fprintf(stderr, "Error: invalid arguments\n");
         TRAP_DEFAULT_FINALIZATION()
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 1;
      }
   }

   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   if (script_path == NULL || *script_path == 0) {
      fprintf(stderr, "Error: lua script path not specified\n");
      return 1;
   }

   luaVM = create_lua_context(script_path);
   if (luaVM == NULL) {
      return 1;
   }

   /* Main loop. */
   while (!stop) {
      /* Receive message. */
      ret = trap_recv(0, &rec_in, &rec_size);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         module_state = STATE_TEMPLATE_RECV;
         const char *spec;
         if (get_input_ifc(&tmplt_in, &spec, &data_fmt) ||
             set_output_ifc(&tmplt_out, &rec_out, spec)) {
            fprintf(stderr, "Error: change of input and output template failed\n");
            module_status = 1;
            break;
         }

         lua_getglobal(luaVM, ON_TEMPLATE_RECV_NAME);
         lua_call(luaVM, 0, 0);
      } else if (ret != TRAP_E_OK) {
         TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, module_status = 1; break)
      }
      module_state = STATE_RECORD_RECV;

      /* Check for null record. */
      if (rec_size <= 1) {
         /* Forward null record to output interface. */
         if (eof) {
            trap_send(0, "", 1);
         }
         break; //TODO: continue or exit?
      }
      record_count++;
      drop_message = 0;

      /* Copy input fields to output template. */
      ur_copy_fields(tmplt_out, rec_out, tmplt_in, rec_in);

      lua_pushnumber(luaVM, record_count);
      lua_setglobal(luaVM, REC_COUNT_NAME);

      lua_getglobal(luaVM, ON_RECORD_RECV_NAME);
      lua_call(luaVM, 0, 0);

      if (!drop_message) {
         /* Send altered message to output interface. */
         rec_size = ur_rec_size(tmplt_out, rec_out);
         trap_send(0, rec_out, rec_size);
      }
   }

   /* Cleanup. */
   lua_close(luaVM);
   if (tmplt_in != NULL) {
      ur_free_template(tmplt_in);
   }
   if (tmplt_out != NULL) {
      ur_free_template(tmplt_out);
   }
   if (rec_out != NULL) {
      ur_free_record(rec_out);
   }
   ur_finalize();
   TRAP_DEFAULT_FINALIZATION()

   return module_status;
}
