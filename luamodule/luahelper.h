/**
 * \file luahelper.h
 * \brief Helping functions for LUA interaction.
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
#ifndef LUAMODULE_LUAHELPER_H
#define LUAMODULE_LUAHELPER_H

#include <lua.h>
#include <unirec/unirec.h>

/**
 * \brief Create LUA context, load script, register API functions and perform checks.
 *
 * \param [in] script_path Path to script file.
 * \return Pointer to created context, NULL on failure.
 */
lua_State *create_lua_context(const char *script_path);

/**
 * \brief Set error in LUA function call.
 *
 * \param [out] luaVM Lua context.
 * \param [in] fmt Printf like format.
 * \param [in] ... Arguments to format specifier.
 */
void set_error(lua_State *luaVM, const char *fmt, ...);

/**
 * \brief Mask IP address from LUA script.
 *
 * \param [out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int ip_mask(lua_State *luaVM);

/**
 * \brief Create IP address object on LUA stack with custom metatable.
 *
 * \param [out] luaVM Lua context.
 * \param [in] ip IP address.
 */
void ip_create_meta(lua_State *luaVM, ip_addr_t ip);

/**
 * \brief Send value (of static size) to LUA stack.
 *
 * \param [out] luaVM Lua context.
 * \param [in] ptr Pointer to value.
 * \param [in] type Type of value to be stored in `ptr`.
 */
void value_send_to_lua(lua_State *luaVM, void *ptr, int type);

/**
 * \brief Send array of values to LUA stack as a table.
 *
 * \param [out] luaVM Lua context.
 * \param [in] array Pointer to values.
 * \param [in] elem_size Size of a single element.
 * \param [in] elem_cnt Number of elements in `array`.
 * \param [in] type Type of values to be stored in `array`.
 */
void table_send_to_lua(lua_State *luaVM, void *array, int elem_size, int elem_cnt, int type);

/**
 * \brief Send unirec field to LUA stack.
 *
 * \param [out] luaVM Lua context.
 * \param [in] tmplt Unirec template.
 * \param [in] rec Unirec record.
 * \param [in] field_id ID of the requested field.
 */
void field_send_to_lua(lua_State *luaVM, const ur_template_t *tmplt, const void *rec, int field_id);

/**
 * \brief Get value (of static size) from LUA stack.
 *
 * \param [out] luaVM Lua context.
 * \param [in] arg_offset Offset of the LUA object on stack.
 * \param [out] ptr Pointer to value.
 * \param [in] type Type of value to be stored in `ptr`.
 * \return 0 on success, 1 failure.
 */
int value_get_from_lua(lua_State *luaVM, int arg_offset, void *ptr, int type);

/**
 * \brief Get array of values (of static size) from table on LUA stack.
 *
 * \param [out] luaVM Lua context.
 * \param [in] arg_offset Offset of the LUA object on stack.
 * \param [out] array Pointer, where buffer with values will be stored (must be freed with free() on success).
 * \param [in] elem_size Size of a single element.
 * \param [out] elem_cnt Number of stored elements in `array`.
 * \param [in] type Type of value to be stored in `array`.
 * \return 0 on success (output pointer must be freed), 1 failure.
 */
int table_get_from_lua(lua_State *luaVM, int arg_offset, void **array, int elem_size, int *elem_cnt, int type);

/**
 * \brief Send unirec field to LUA stack.
 *
 * \param [out] luaVM Lua context.
 * \param [in] arg_offset Offset of the LUA object on stack.
 * \param [in] tmplt Unirec template.
 * \param [in, out] rec Unirec record.
 * \param [in] field_id ID of the requested field.
 * \return 0 on success, 1 failure.
 */
int field_get_from_lua(lua_State *luaVM, int arg_offset, const ur_template_t *tmplt, void *rec, int field_id);

#endif /* LUAMODULE_LUAHELPER_H */
