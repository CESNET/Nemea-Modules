/**
 * \file luahelper.c
 * \brief Source code of helping functions for LUA interaction.
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
#include <math.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <unirec/unirec.h>

#include "luahelper.h"
#include "luamodule.h"
#include "luafuncs.h"

lua_State *create_lua_context(const char *script_path)
{
   lua_State *luaVM;
   int ret;

   /* Create LUA context. */
   luaVM = luaL_newstate();
   luaL_openlibs(luaVM);
   lua_settop(luaVM, 0);

   /* Register LUA API functions. */
   lua_register(luaVM, GET_FUNC_NAME, field_get);
   lua_register(luaVM, SET_FUNC_NAME, field_set);
   lua_register(luaVM, ADD_FUNC_NAME, field_add);
   lua_register(luaVM, DEL_FUNC_NAME, field_del);
   lua_register(luaVM, TYPE_FUNC_NAME, field_type);
   lua_register(luaVM, IP_FUNC_NAME, field_ip);
   lua_register(luaVM, IP4_FUNC_NAME, field_ip_is4);
   lua_register(luaVM, IP6_FUNC_NAME, field_ip_is6);
   lua_register(luaVM, ID_FUNC_NAME, field_getid);

   /* Load functions from script. */
   ret = luaL_dofile(luaVM, script_path);
   if (ret != 0) {
       fprintf(stderr, "Error: calling %s script failed: %s\n", script_path, lua_tostring(luaVM, -1));
       lua_close(luaVM);
       return NULL;
   }

   lua_getglobal(luaVM, ON_RECORD_RECV_NAME);
   if (lua_isnil(luaVM, 1)) {
       fprintf(stderr, "Error: lua script must to contain on_record_recv function\n");
       lua_close(luaVM);
       return NULL;
   }
   lua_pop(luaVM, 1);

   module_state = STATE_INIT;
   /* Execute LUA init routine. */
   lua_getglobal(luaVM, ON_INIT_NAME);
   if (lua_isnil(luaVM, 1)) {
      lua_pop(luaVM, 1);
   } else {
      lua_call(luaVM, 0, 0);
   }

   /* Check if ON_TEMPLATE_RECV_NAME function exists. */
   lua_getglobal(luaVM, ON_TEMPLATE_RECV_NAME);
   if (lua_isnil(luaVM, 1)) {
      /* Register dummy function. */
      lua_pop(luaVM, 1);
      lua_register(luaVM, ON_TEMPLATE_RECV_NAME, noop_func);
   }

   return luaVM;
}

void set_error(lua_State *luaVM, const char *fmt, ...)
{
   char tmp[4096];
   va_list args;

   va_start(args, fmt);
   vsnprintf(tmp, sizeof(tmp), fmt, args);
   va_end(args);

   lua_pushstring(luaVM, tmp);
   lua_error(luaVM);
}

int ip_mask(lua_State *luaVM)
{
   int mask = 0;
   int n = lua_gettop(luaVM);
   ip_addr_t ip;

   if (n != 2) {
      set_error(luaVM, "Invalid arguments to IP mask operation");
      return 0;
   }
   if (lua_type(luaVM, 1) == LUA_TUSERDATA) {
      ip = *(ip_addr_t *) lua_touserdata(luaVM, 1);
   } else {
      set_error(luaVM, "Invalid arguments to IP mask operation, expected IP userdata as first operand");
      return 0;
   }
   if (lua_type(luaVM, 2) == LUA_TNUMBER) {
      mask = lua_tonumber(luaVM, 2);
   } else {
      set_error(luaVM, "Invalid arguments to IP mask operation, expected number as second operand");
      return 0;
   }

   if (ip_is4(&ip) && (mask < 0 || mask > 32)) {
      set_error(luaVM, "Invalid mask '%d' for IPv4 address", mask);
      return 0;
   }
   if (ip_is6(&ip) && (mask < 0 || mask > 128)) {
      set_error(luaVM, "Invalid mask '%d' for IPv6 address", mask);
      return 0;
   }

   if (ip_is4(&ip)) {
      int bits = 32 - mask;
      uint32_t tmp = ntohl(ip.ui32[2]);
      ip.ui32[2] = htonl(tmp & ~(((uint64_t) 1 << bits) - 1));
   } else {
      int bits = 128 - mask;
      for (int i = 3; i >= 0 && bits > 0; i--) {
         ip.ui32[i] = ntohl(ntohl(ip.ui32[i]) & ~(((uint64_t) 1 << (bits > 32 ? 32 : bits)) - 1));
         bits -= 32;
      }
   }

   ip_create_meta(luaVM, ip);
   return 1;
}

int ip_tostring(lua_State *luaVM)
{
   char ip_str[INET6_ADDRSTRLEN];
   ip_addr_t *ip;

   if (lua_gettop(luaVM) != 1 || lua_type(luaVM, 1) != LUA_TUSERDATA) {
      set_error(luaVM, "Expected IP address userdata");
      return 0;
   }

   ip = lua_touserdata(luaVM, 1);
   ip_to_str(ip, ip_str);
   lua_pushstring(luaVM, ip_str);

   return 1;
}

int ip_eq(lua_State *luaVM)
{
   char ip_str1_[INET6_ADDRSTRLEN];
   char ip_str2_[INET6_ADDRSTRLEN];
   const char *ip_str1 = ip_str1_;
   const char *ip_str2 = ip_str2_;
   ip_addr_t *ip;

   if (lua_gettop(luaVM) != 2) {
      set_error(luaVM, "Expected IP address userdata and one additional argument");
      return 0;
   }

   if (lua_type(luaVM, 1) == LUA_TUSERDATA) {
      ip = lua_touserdata(luaVM, 1);
      ip_to_str(ip, ip_str1_);
   } else if (lua_type(luaVM, 1) == LUA_TSTRING) {
      ip_str1 = lua_tostring(luaVM, 1);
   } else {
      lua_pushboolean(luaVM, 0);
      return 1;
   }

   if (lua_type(luaVM, 2) == LUA_TUSERDATA) {
      ip = lua_touserdata(luaVM, 2);
      ip_to_str(ip, ip_str2_);
   } else if (lua_type(luaVM, 2) == LUA_TSTRING) {
      ip_str2 = lua_tostring(luaVM, 2);
   } else {
      lua_pushboolean(luaVM, 0);
      return 1;
   }

   lua_pushboolean(luaVM, !strcmp(ip_str1, ip_str2));

   return 1;
}

void ip_create_meta(lua_State *luaVM, ip_addr_t ip)
{
   ip_addr_t *block = lua_newuserdata(luaVM, sizeof(ip));
   *block = ip;

   lua_createtable(luaVM, 0, 2);

   lua_pushstring(luaVM, "__div");
   lua_pushcfunction(luaVM, ip_mask);
   lua_settable(luaVM, -3);

   lua_pushstring(luaVM, "__eq");
   lua_pushcfunction(luaVM, ip_eq);
   lua_settable(luaVM, -3);

   lua_pushstring(luaVM, "__tostring");
   lua_pushcfunction(luaVM, ip_tostring);
   lua_settable(luaVM, -3);

   lua_setmetatable(luaVM, -2);
}

void value_send_to_lua(lua_State *luaVM, void *ptr, int type)
{
   switch (type) {
      case UR_TYPE_TIME:
         lua_pushnumber(luaVM, ((double) ur_time_get_sec(*(ur_time_t *) ptr) + (double) ur_time_get_usec(*(ur_time_t *) ptr) / 1000000));
         break;
      case UR_TYPE_IP:
         ip_create_meta(luaVM, *((ip_addr_t *) ptr));
         break;
      case UR_TYPE_MAC:
         {
            char mac_str[MAC_STR_LEN];
            mac_to_str((mac_addr_t *) ptr, mac_str);
            lua_pushstring(luaVM, mac_str);
            break;
         }
      case UR_TYPE_UINT8:
         lua_pushnumber(luaVM, *((uint8_t *) ptr));
         break;
      case UR_TYPE_UINT16:
         lua_pushnumber(luaVM, *((uint16_t *) ptr));
         break;
      case UR_TYPE_UINT32:
         lua_pushnumber(luaVM, *((uint32_t *) ptr));
         break;
      case UR_TYPE_UINT64:
         lua_pushnumber(luaVM, *((uint64_t *) ptr));
         break;
      case UR_TYPE_INT8:
         lua_pushnumber(luaVM, *((int8_t *) ptr));
         break;
      case UR_TYPE_INT16:
         lua_pushnumber(luaVM, *((int16_t *) ptr));
         break;
      case UR_TYPE_INT32:
         lua_pushnumber(luaVM, *((int32_t *) ptr));
         break;
      case UR_TYPE_INT64:
         lua_pushnumber(luaVM, *((int64_t *) ptr));
         break;
      case UR_TYPE_FLOAT:
         lua_pushnumber(luaVM, *((float *) ptr));
         break;
      case UR_TYPE_DOUBLE:
         lua_pushnumber(luaVM, *((double *) ptr));
         break;
      case UR_TYPE_STRING:
      case UR_TYPE_BYTES:
         lua_pushnil(luaVM);
         break;
      default:
         lua_pushnil(luaVM);
         break;
   }
}

void table_send_to_lua(lua_State *luaVM, void *array, int elem_size, int elem_cnt, int type)
{
   int i = 0;

   lua_createtable(luaVM, i, 0);
   while (i < elem_cnt) {
      /* Push key, index from 1. */
      lua_pushnumber(luaVM, i + 1);

      /* Push value. */
      value_send_to_lua(luaVM, ((char *) array) + i * elem_size, type);

      /* Remove nil elements. */
      if (lua_isnil(luaVM, lua_gettop(luaVM))) {
         lua_pop(luaVM, 2);
         continue;
      }
      /* Set key/val to table. */
      lua_settable(luaVM, -3);
      i++;
   }
}

void field_send_to_lua(lua_State *luaVM, const ur_template_t *tmplt, const void *rec, int field_id)
{
   if (ur_is_present(tmplt, field_id)) {
      /* Get pointer to currently processed field. */
      void *ptr = ur_get_ptr_by_id(tmplt, rec, field_id);
      int type = ur_get_type(field_id);

      if (type == UR_TYPE_STRING || type == UR_TYPE_BYTES) {
         lua_pushlstring(luaVM, ptr, ur_get_var_len(tmplt, rec, field_id));
      } else if (ur_is_varlen(field_id)) {
         int elem_size = ur_array_get_elem_size(field_id);
         int elem_cnt = ur_array_get_elem_cnt(tmplt, rec, field_id);

         type = ur_array_get_elem_type(field_id);
         table_send_to_lua(luaVM, ptr, elem_size, elem_cnt, type);
      } else {
         value_send_to_lua(luaVM, ptr, type);
      }
   } else {
      lua_pushnil(luaVM);
   }
}

int value_get_from_lua(lua_State *luaVM, int arg_offset, void *ptr, int type)
{
   switch (type) {
      case UR_TYPE_TIME:
         {
            if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
               return 1;
            }
            double tmp = lua_tonumber(luaVM, arg_offset);
            *((ur_time_t *) ptr) = ur_time_from_sec_usec(floor(tmp), tmp - floor(tmp));
            break;
         }
      case UR_TYPE_IP:
         {
            if (lua_type(luaVM, arg_offset) != LUA_TUSERDATA) {
               return 1;
            }
            *((ip_addr_t *) ptr) = *(ip_addr_t *) lua_touserdata(luaVM, arg_offset);
            break;
         }
      case UR_TYPE_MAC:
         {
            if (lua_type(luaVM, arg_offset) != LUA_TSTRING) {
               return 1;
            }
            const char *mac_str = lua_tostring(luaVM, arg_offset);
            mac_addr_t mac;
            if (mac_from_str(mac_str, &mac) == 0) {
               return 1;
            }
            *((mac_addr_t *) ptr) = mac;
            break;
         }
      case UR_TYPE_UINT8:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((uint8_t *) ptr) = (uint8_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_UINT16:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((uint16_t *) ptr) = (uint16_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_UINT32:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((uint32_t *) ptr) = (uint32_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_UINT64:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((uint64_t *) ptr) = (uint64_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_INT8:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((int8_t *) ptr) = (int8_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_INT16:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((int16_t *) ptr) = (int16_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_INT32:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((int32_t *) ptr) = (int32_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_INT64:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((int64_t *) ptr) = (int64_t) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_FLOAT:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((float *) ptr) = (float) lua_tonumber(luaVM, arg_offset);
         break;
      case UR_TYPE_DOUBLE:
         if (lua_type(luaVM, arg_offset) != LUA_TNUMBER) {
            return 1;
         }
         *((double *) ptr) = (double) lua_tonumber(luaVM, arg_offset);
         break;
      default:
         set_error(luaVM, "Field of type '%s' is not supported yet", ur_field_type_str[type]);
         return 1;
   }

   return 0;
}

int table_get_from_lua(lua_State *luaVM, int arg_offset, void **array, int elem_size, int *elem_cnt, int type)
{
   int i;
   if (!lua_istable(luaVM, arg_offset)) {
      set_error(luaVM, "Expected table");
      return 1;
   }

#if LUA_VERSION_NUM >= 502
   lua_len(luaVM, arg_offset);
   *elem_cnt = lua_tonumber(luaVM, -1);
   lua_pop(luaVM, 1);
#else
   *elem_cnt = lua_objlen(luaVM, arg_offset);
#endif

   *array = (void *) malloc(*elem_cnt * elem_size);

   for (i = 0; i < *elem_cnt; i++) {
      lua_pushnumber(luaVM, i + 1);
      lua_gettable(luaVM, arg_offset);

      if (value_get_from_lua(luaVM, -1, ((char *) *array) + i * elem_size, type)) {
         lua_pop(luaVM, 1);
         free(*array);
         *array = NULL;
         *elem_cnt = 0;
         return 1;
      }

      lua_pop(luaVM, 1);
   }

   return 0;
}

int field_get_from_lua(lua_State *luaVM, int arg_offset, const ur_template_t *tmplt, void *rec, int field_id)
{
   if (ur_is_present(tmplt, field_id)) {
      void *ptr = ur_get_ptr_by_id(tmplt, rec, field_id);
      int type = ur_get_type(field_id);

      if (type == UR_TYPE_STRING || type == UR_TYPE_BYTES) {
         size_t bytes_len;
         const char *bytes;
         if (lua_type(luaVM, arg_offset) != LUA_TSTRING) {
            return 1;
         }
         bytes = lua_tolstring(luaVM, arg_offset, &bytes_len);
         ur_set_var(tmplt, rec, field_id, bytes, bytes_len);
      } else if (ur_is_varlen(field_id)) {
         void *array_tmp;
         int elem_size = ur_array_get_elem_size(field_id);
         int elem_cnt = 0;

         type = ur_array_get_elem_type(field_id);
         if (table_get_from_lua(luaVM, arg_offset, &array_tmp, elem_size, &elem_cnt, type)) {
            return 1;
         }

         ur_array_allocate(tmplt, rec, field_id, elem_cnt);
         ptr = ur_get_ptr_by_id(tmplt, rec, field_id);
         memcpy(ptr, array_tmp, elem_cnt * elem_size);
         free(array_tmp);
      } else {
         return value_get_from_lua(luaVM, arg_offset, ptr, type);
      }
   } else {
      return 1;
   }

   return 0;
}
