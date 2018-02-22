/**
 * \file unirecfilter.h
 * \brief NEMEA module selecting records and sending specified fields.
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
#ifndef UNIRECFILTER_H
#define UNIRECFILTER_H

#include <unirec/unirec.h>
#include <sys/types.h>
#include <regex.h>

#define DYN_FIELD_MAX_SIZE 1024 // Maximal size of dynamic field, longer fields will be cutted to this size

#define SET_NULL(field_id, tmpl, data) \
memset(ur_get_ptr_by_id(tmpl, data, field_id), 0, ur_get_size(field_id));

extern char * str_buffer;

#endif

