/**
 * \file template.h
 * \brief Functions for manipulation with unirec templates and trap IFCs.
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
#ifndef LUAMODULE_TEMPLATE_H
#define LUAMODULE_TEMPLATE_H

#include <unirec/unirec.h>

#include <lua.h>

/**
 * \brief Function gets unirec template, format and template specification
 *    string from input interface.
 *
 * \param [in, out] tmplt Unirec template.
 * \param [out] spec Unirec template specification string.
 * \param [out] data_fmt Data format used at input interface.
 * \return 0 on success, 1 otherwise.
 */
int get_input_ifc(ur_template_t **tmplt, const char **spec, uint8_t *data_fmt);

/**
 * \brief Function sets unirec template string specification
 *    to output interface and returns unirec template and record
 *    based on that specification.
 *
 * \param [in, out] tmplt Unirec template.
 * \param [out] rec Unirec record.
 * \param [in] spec Unirec template specification string.
 * \return 0 on success, 1 otherwise.
 */
int set_output_ifc(ur_template_t **tmplt, void **rec, const char *spec);

/**
 * \brief Remove commas from the beginning and the end of string and sequnces
 *    of commas from unirec template string specfication.
 *
 * \param [in, out] spec Unirec template string specification.
 */
void template_spec_trim(char *spec);

/**
 * \brief Add unirec template fields specification from LUA stack to
 *    unirec template string specification created from template.
 *
 * \param [in, out] luaVM Lua context.
 * \param [in] tmplt Unirec template
 * \return Unirec template field specification.
 */
char *template_spec_construct(lua_State *luaVM, ur_template_t *tmplt);

/**
 * \brief Remove specified field from input unirec template string specification.
 *
 * \param [in] spec Unirec template string specification.
 * \param [in] field Unirec template field name.
 * \return 0 on success - field was found and replaced with ' ', 1 when not found.
 */
int template_spec_delete_field(char *spec, const char *field);

#endif /* LUAMODULE_TEMPLATE_H */
