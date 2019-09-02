/**
 * \file template.c
 * \brief Source functions for manipulation with unirec templates and trap IFCs.
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
#include <string.h>
#include <ctype.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "template.h"
#include "luamodule.h"

int get_input_ifc(ur_template_t **tmplt, const char **spec, uint8_t *data_fmt)
{
   /* Get new data format used on input interface. */
   if (trap_get_data_fmt(TRAPIFC_INPUT, 0, data_fmt, spec) != TRAP_E_OK) {
      return 1;
   }

   /* Update input template. */
   *tmplt = ur_define_fields_and_update_template(*spec, *tmplt);
   if (*tmplt == NULL) {
      return 1;
   }

   return 0;
}

int set_output_ifc(ur_template_t **tmplt, void **rec, const char *spec)
{
   /* Create output template based on IFC spec. */
   *tmplt = ur_define_fields_and_update_template(spec, *tmplt);
   if (*tmplt == NULL) {
      return 1;
   }

   /* Set IFC spec to output interface. */
   trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec);

   if (*rec != NULL) {
      ur_free_record(*rec);
   }

   /* Create output record based on IFC spec. */
   *rec = ur_create_record(*tmplt, UR_MAX_SIZE);
   if (*rec == NULL) {
      return 1;
   }

   return 0;
}

void template_spec_trim(char *spec)
{
   size_t spec_len = strlen(spec);
   int i;

   /* Remove commas from the beginning and the end of spec string. */
   for (i = 0; i < spec_len && (spec[i] == ',' || isspace(spec[i])); i++) {
      spec[i] = ' ';
   }
   for (i = spec_len - 1; i >= 0 && (spec[i] == ',' || isspace(spec[i])); i--) {
      spec[i] = ' ';
   }

   /* Remove sequences of commas (e.g. "uint32 FOO,, ,uint16 BAR,")
    * from spec that may cause problems. */
   int comma_found = 0;
   for (i = 0; i < spec_len; i++) {
      if (comma_found && spec[i] == ',') {
         spec[i] = ' ';
      } else if (spec[i] == ',') {
         comma_found = 1;
      } else if (!isspace(spec[i])) {
         comma_found = 0;
      }
   }
}

char *template_spec_construct(lua_State *luaVM, ur_template_t *tmplt)
{
   int n = lua_gettop(luaVM);
   int i;

   char *spec = ur_template_string_delimiter(tmplt, ',');
   const char *fields;
   size_t spec_len = strlen(spec);
   size_t fields_len;

   /* Iterate through function arguments. */
   for (i = 1; i <= n; i++) {
      if (lua_type(luaVM, i) == LUA_TSTRING) {
         fields = lua_tolstring(luaVM, i, &fields_len);

         /* Append field(s) to existing template spec. */
         spec[spec_len] = ',';
         spec_len++;

         char *tmp = realloc(spec, spec_len + fields_len + 1);
         if (tmp == NULL) {
            free(spec);
            return NULL;
         }
         spec = tmp;
         memcpy(spec + spec_len, fields, fields_len);

         spec_len += fields_len;
         spec[spec_len] = 0;
      } else {
         free(spec);
         return NULL;
      }
   }

   /* Remove any sequences of commas that may cause problems, also remove
    * commas from begin and end of string. */
   template_spec_trim(spec);

   return spec;
}

int template_spec_delete_field(char *spec, const char *field)
{
   size_t field_len = strlen(field);
   char *begin = strstr(spec, field);
   char *end = begin + field_len;

   /* Find beginning of the correct (skip prefixes of different fields) unirec field. */
   while (1) {
      if (begin == NULL) {
         return 1;
      }
      /* Check if field is not PREFIX. e.g. "BY" in "BYTES". */
      if (begin == spec || (*(begin - 1) == ',' || isspace(*(begin - 1)))) {
         /* Check if field is not SUFIX. e.g. "TES" in "BYTES". */
         if (*end == 0 || *end == ',' || isspace(*end)) {
            break;
         }
      }

      begin = strstr(begin + 1, field);
      end = begin + field_len;
   }

   /* Find begin of field type. */
   while (begin > spec && *begin != ',') {
      begin--;
   }
   /* Replace field with spaces. */
   for (; begin < end; begin++) {
      *begin = ' ';
   }

   return 0;
}

