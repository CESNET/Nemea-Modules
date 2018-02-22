/**
 * \file libunirecfilter.h
 * \brief NEMEA library for matching UniRec
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
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *   may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
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

#ifndef LIBUNIRECFILTER_H
#define LIBUNIRECFILTER_H

#include <unirec/unirec.h>

#define URFILTER_TRUE 1
#define URFILTER_FALSE 0
#define URFILTER_ERROR (-1)

typedef struct urfilter_s {
   char *filter;
   void *tree;
   const char *ifc_identifier;
} urfilter_t;

/**
 *
 * \param[in] ifc_identifier Identification of TRAP IFC where the filter is used.
 * \return Pointer to urfilter internal memory, NULL on error.
 */
urfilter_t *urfilter_create(const char *filter_str, const char *ifc_identifier);

/**
 *
 * \return URFILTER_TRUE on success and URFILTER_ERROR on syntax error.
 */
int urfilter_compile(urfilter_t *unirec_filter);

/**
 *
 * \return Result of condition eval: URFILTER_TRUE/URFILTER_FALSE. URFILTER_ERROR on syntax error.
 */
int urfilter_match(urfilter_t *unirec_filter, const ur_template_t *template, const void *record);

void urfilter_destroy(urfilter_t *object);

#endif /* LIBUNIRECFILTER_H */
