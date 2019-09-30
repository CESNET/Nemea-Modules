/**
 * \file luafuncs.h
 * \brief Header file containing LUA functions for registration and usage in scripts.
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
#ifndef LUAMODULE_LUAFUNCS_H
#define LUAMODULE_LUAFUNCS_H

#include <lua.h>

/**
 * \brief Dummy function for LUA API.
 *
 * \param luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int noop_func(lua_State *luaVM);

/**
 * \brief Getter function for reading fields from unirec record.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_get(lua_State *luaVM);

/**
 * \brief Setter function for writing values into fields in unirec record.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_set(lua_State *luaVM);

/**
 * \brief Function for adding new unirec fields into output template.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_add(lua_State *luaVM);

/**
 * \brief Function for removing unirec fields from output template.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_del(lua_State *luaVM);

/**
 * \brief Getter function for unirec field type.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_type(lua_State *luaVM);

/**
 * \brief Getter function for unirec field type.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_ip(lua_State *luaVM);

/**
 * \brief Check IP for version.
 *
 * \param [in, out] luaVM Lua context.
 * \param [in] version Version of IP to check.
 * \return Number of parameter left on stack.
 */
int field_ip_is(lua_State *luaVM, int version);

/**
 * \brief Check if IP has version 4.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_ip_is4(lua_State *luaVM);

/**
 * \brief Check if IP has version 6.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_ip_is6(lua_State *luaVM);

/**
 * \brief Get field ID of unirec field.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_getid(lua_State *luaVM);

/**
 * \brief Drop unirec message.
 *
 * \param [in, out] luaVM Lua context.
 * \return Number of parameter left on stack.
 */
int field_drop(lua_State *luaVM);

#endif /* LUAMODULE_LUAFUNCS_H */
