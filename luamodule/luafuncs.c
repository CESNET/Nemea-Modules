/**
 * \file luafuncs.c
 * \brief Source code with C functions for LUA function registration.
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
#include <unirec/unirec.h>

#include <lua.h>

#include "luamodule.h"
#include "luafuncs.h"
#include "luahelper.h"
#include "template.h"

int noop_func(lua_State *luaVM)
{
   return 0;
}

int field_get(lua_State *luaVM)
{
   int field_id;
   int n = lua_gettop(luaVM);
   int i;

   if (module_state != STATE_RECORD_RECV) {
      set_error(luaVM, "'%s' function may be called only in '%s' function", GET_FUNC_NAME, ON_RECORD_RECV_NAME);
      return 0;
   }

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i++) {
      if (lua_type(luaVM, i) == LUA_TSTRING) {
         field_id = ur_get_id_by_name(lua_tostring(luaVM, i));
         if (field_id < 0) {
            lua_pushnil(luaVM);
            continue;
         }
      } else if (lua_type(luaVM, i) == LUA_TNUMBER) {
         field_id = lua_tonumber(luaVM, i);
         if (!ur_is_present(tmplt_in, field_id)) {
            lua_pushnil(luaVM);
            continue;
         }
      } else {
         set_error(luaVM, "Incorrect argument(s) to '%s'", GET_FUNC_NAME);
      }

      field_send_to_lua(luaVM, tmplt_in, rec_in, field_id);
   }

   if (n == 0) {
      ur_field_id_t id = UR_ITER_BEGIN;
      i = 0;

      lua_createtable(luaVM, 0, tmplt_in->count);

      /* Iterate over fields. */
      while ((id = ur_iter_fields_record_order(tmplt_in, i++)) != UR_ITER_END) {
         /* Push key. */
         lua_pushstring(luaVM, ur_get_name(id));
         /* Push value. */
         field_send_to_lua(luaVM, tmplt_in, rec_in, id);
         /* Remove nil elements. */
         if (lua_isnil(luaVM, lua_gettop(luaVM))) {
            lua_pop(luaVM, 2);
            continue;
         }
         /* Set key/val to table. */
         lua_settable(luaVM, 1);
      }
      return 1;
   }

   return n;
}

int field_set(lua_State *luaVM)
{
   int field_id;
   int n = lua_gettop(luaVM);
   int i;
   int ret_cnt = n / 2;

   if (module_state != STATE_RECORD_RECV) {
      set_error(luaVM, "'%s' function may be called only in '%s' function", SET_FUNC_NAME, ON_RECORD_RECV_NAME);
      return 0;
   }

   if (n % 2 || n == 0) {
      set_error(luaVM, "invalid arguments in '%s' function", SET_FUNC_NAME);
      return 0;
   }

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i+=2) {
      if (lua_type(luaVM, i) == LUA_TSTRING) {
         field_id = ur_get_id_by_name(lua_tostring(luaVM, i));
         if (field_id < 0) {
            /* Parsing failed - push false. */
            lua_pushboolean(luaVM, 0);
            continue;
         }
      } else if (lua_type(luaVM, i) == LUA_TNUMBER) {
         field_id = lua_tonumber(luaVM, i);
         if (!ur_is_present(tmplt_out, field_id)) {
            /* Parsing failed - push false. */
            lua_pushboolean(luaVM, 0);
            continue;
         }
      } else {
         set_error(luaVM, "Incorrect argument(s) to '%s'", SET_FUNC_NAME);
         break;
      }

      if (field_get_from_lua(luaVM, i + 1, tmplt_out, rec_out, field_id)) {
         /* Parsing failed - push false. */
         lua_pushboolean(luaVM, 0);
      } else {
         /* Parsing succeded - push true. */
         lua_pushboolean(luaVM, 1);
      }
   }

   return ret_cnt;
}

int field_add(lua_State *luaVM)
{
   char *spec;
   ur_template_t *tmplt_tmp = NULL;

   if (lua_gettop(luaVM) == 0) {
      set_error(luaVM, "no arguments specified to '%s' function", ADD_FUNC_NAME);
      return 0;
   }

   if (module_state != STATE_TEMPLATE_RECV) {
      set_error(luaVM, "'%s' function may be called only in '%s' function", ADD_FUNC_NAME, ON_TEMPLATE_RECV_NAME);
      return 0;
   }

   spec = template_spec_construct(luaVM, tmplt_out);
   if (spec == NULL) {
      set_error(luaVM, "Function '%s' failed on argument parsing", ADD_FUNC_NAME);
      return 0;
   }

   if (set_output_ifc(&tmplt_tmp, &rec_out, spec)) {
      free(spec);
      lua_pushboolean(luaVM, 0);
      return 1;
   }
   lua_pushboolean(luaVM, 1);
   ur_free_template(tmplt_out);
   tmplt_out = tmplt_tmp;

   free(spec);
   return 1;
}

int field_del(lua_State *luaVM)
{
   int n = lua_gettop(luaVM);
   int i;
   char *spec;
   const char *field;
   ur_template_t *tmplt_tmp = NULL;

   if (module_state != STATE_TEMPLATE_RECV) {
      set_error(luaVM, "'%s' function may be called only in '%s' function", DEL_FUNC_NAME, ON_TEMPLATE_RECV_NAME);
      return 0;
   }

   if (n == 0) {
      spec = malloc(sizeof(char));
      if (spec == NULL) {
         set_error(luaVM, "malloc() failed");
         return 0;
      }
      spec[0] = 0;
   } else {
      spec = ur_template_string_delimiter(tmplt_out, ',');
   }

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i++) {
      if (lua_type(luaVM, i) == LUA_TSTRING) {
         field = lua_tostring(luaVM, i);
         lua_pushboolean(luaVM, !template_spec_delete_field(spec, field));
      } else if (lua_type(luaVM, i) == LUA_TNUMBER) {
         int field_id = lua_tonumber(luaVM, i);
         if (!ur_is_present(tmplt_in, field_id)) {
            lua_pushboolean(luaVM, 0);
            continue;
         }
         field = ur_get_name(field_id);
         lua_pushboolean(luaVM, !template_spec_delete_field(spec, field));
      } else {
         free(spec);
         set_error(luaVM, "Incorrect argument(s) to '%s'", DEL_FUNC_NAME);
         return 0;
      }
   }

   template_spec_trim(spec);
   if (set_output_ifc(&tmplt_tmp, &rec_out, spec)) {
      free(spec);
      set_error(luaVM, "Function '%s' failed to set output template", DEL_FUNC_NAME);
      return 0;
   }
   ur_free_template(tmplt_out);
   tmplt_out = tmplt_tmp;

   free(spec);
   return n;
}

int field_type(lua_State *luaVM)
{
   int field_id;
   int n = lua_gettop(luaVM);
   int i;

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i++) {
      if (lua_type(luaVM, i) == LUA_TSTRING) {
         field_id = ur_get_id_by_name(lua_tostring(luaVM, i));
         if (field_id < 0) {
            lua_pushnil(luaVM);
            continue;
         }

         lua_pushstring(luaVM, ur_field_type_str[ur_get_type(field_id)]);
      } else {
         set_error(luaVM, "Incorrect argument(s) to '%s'", TYPE_FUNC_NAME);
         return 0;
      }
   }

   if (n == 0) {
      ur_field_id_t id = UR_ITER_BEGIN;
      i = 0;

      lua_createtable(luaVM, 0, tmplt_out->count);

      /* Iterate over fields. */
      while ((id = ur_iter_fields_record_order(tmplt_out, i++)) != UR_ITER_END) {
         /* Push key. */
         lua_pushstring(luaVM, ur_get_name(id));
         /* Push value. */
         lua_pushstring(luaVM, ur_field_type_str[ur_get_type(id)]);
         /* Set key/val to table. */
         lua_settable(luaVM, 1);
      }
      return 1;
   }
   return n;
}

int field_ip(lua_State *luaVM)
{
   int n = lua_gettop(luaVM);
   int i;
   ip_addr_t ip;

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i++) {
      if (lua_type(luaVM, i) == LUA_TSTRING) {
         if (ip_from_str(lua_tostring(luaVM, i), &ip) == 0) {
            lua_pushnil(luaVM);
            continue;
         }
         ip_create_meta(luaVM, ip);
      } else {
         set_error(luaVM, "Incorrect argument(s) to '%s'", IP_FUNC_NAME);
      }
   }

   return n;
}

int field_ip_is(lua_State *luaVM, int version)
{
   int n = lua_gettop(luaVM);
   int i;
   ip_addr_t *ip;

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i++) {
      if (lua_type(luaVM, i) == LUA_TLIGHTUSERDATA) {
         ip = lua_touserdata(luaVM, i);

         if (version == 4) {
            lua_pushboolean(luaVM, ip_is4(ip));
         } else if (version == 6) {
            lua_pushboolean(luaVM, ip_is6(ip));
         } else {
            lua_pushboolean(luaVM, 0);
         }
      } else {
         char *func_name = "?";
         if (version == 4) {
            func_name = IP4_FUNC_NAME;
         } else if (version == 6) {
            func_name = IP6_FUNC_NAME;
         }
         set_error(luaVM, "Incorrect argument(s) to '%s'", func_name);
      }
   }

   return n;
}

int field_ip_is4(lua_State *luaVM)
{
   return field_ip_is(luaVM, 4);
}

int field_ip_is6(lua_State *luaVM)
{
   return field_ip_is(luaVM, 6);
}

int field_getid(lua_State *luaVM)
{
   int field_id;
   int n = lua_gettop(luaVM);
   int i;

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i++) {
      if (lua_type(luaVM, i) == LUA_TSTRING) {
         field_id = ur_get_id_by_name(lua_tostring(luaVM, i));
         if (field_id < 0) {
            lua_pushnil(luaVM);
            continue;
         }
         lua_pushnumber(luaVM, field_id);
      } else {
         set_error(luaVM, "Incorrect argument(s) to '%s'", ID_FUNC_NAME);
         break;
      }
   }

   return n;
}

int field_drop(lua_State *luaVM)
{
   drop_message = 1;
   return 0;
}
