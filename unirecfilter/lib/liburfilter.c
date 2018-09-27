/**
 * \file unirecfilter.c
 * \brief NEMEA library for matching UniRec
 * \author Klara Drhova <drhovkla@fit.cvut.cz>
 * \author Zdenek Kasner <kasnezde@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Miroslav Kalina <kalinmi2@fit.cvut.cz>
 * \date 2013
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2013-2015 CESNET
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "functions.h"
#include "liburfilter.h"

urfilter_t *urfilter_create(const char *filter_str, const char *ifc_identifier)
{
   // allocate filter structure
   urfilter_t *unirec_filter = (urfilter_t *) calloc(1, sizeof (urfilter_t));

   if (filter_str) {
      unirec_filter->filter = strdup(filter_str);
      unirec_filter->ifc_identifier = ifc_identifier;
   }

   return unirec_filter;
}

int urfilter_compile(urfilter_t *unirec_filter)
{
   // @TODO Verify if template is present in global context (filter keywords MUST be known before compile)

   if (unirec_filter->filter) {
      // parse string filter into AST
      unirec_filter->tree = (void *) getTree(unirec_filter->filter, unirec_filter->ifc_identifier);
      if (unirec_filter->tree == NULL) {
         return URFILTER_ERROR;
      } else {
         return URFILTER_TRUE;
      }
   }

   printf("[URFilter] Unable to compile filter rule. No string filter given.\n");
   return URFILTER_ERROR;
}

int urfilter_match(urfilter_t *unirec_filter, const ur_template_t *template, const void *record)
{
   if (!unirec_filter->tree) {
      if (unirec_filter->filter) {
         if (urfilter_compile(unirec_filter) != URFILTER_TRUE) {
            printf("[URFilter] Syntax error in filter: %s.\n", unirec_filter->filter);
            return URFILTER_ERROR;
         }
      } else {
         printf("[URFilter] Missing filter.\n");
         return URFILTER_ERROR;
      }
   }
   
   // empty filter means always TRUE
   if (!unirec_filter->filter) {
      return URFILTER_TRUE;
   }
   
   if (unirec_filter->tree) {
      return evalAST((struct ast *) unirec_filter->tree, template, record);
   }

   printf("[URFilter] Trying to match UniRec to uninitalized filter. Returning FALSE.\n");
   return URFILTER_FALSE;
}

void urfilter_destroy(urfilter_t *object)
{
   if (object) {
      free(object->filter);
      if (object->tree) {
         freeAST((struct ast *) object->tree);
      }
      free(object);
   }
}
