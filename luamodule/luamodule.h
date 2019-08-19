/**
 * \file luamodule.h
 * \brief Header file containing extern global variables.
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
#ifndef LUAMODULE_MODULE_H
#define LUAMODULE_MODULE_H

#include <unirec/unirec.h>

#define REC_COUNT_NAME        "_REC_COUNT"
#define ON_RECORD_RECV_NAME   "on_record_recv"
#define ON_TEMPLATE_RECV_NAME "on_template_recv"
#define ON_INIT_NAME          "on_init"
#define GET_FUNC_NAME         "ur_get"
#define SET_FUNC_NAME         "ur_set"
#define ADD_FUNC_NAME         "ur_add"
#define DEL_FUNC_NAME         "ur_del"
#define TYPE_FUNC_NAME        "ur_type"
#define IP_FUNC_NAME          "ur_ip"
#define IP4_FUNC_NAME         "ur_ip4"
#define IP6_FUNC_NAME         "ur_ip6"

/**
 * \brief States of the module.
 */
typedef enum module_state_e {
   STATE_INIT,
   STATE_TEMPLATE_RECV,
   STATE_RECORD_RECV
} module_state_t;

/**
 * \brief Input unirec template.
 */
extern ur_template_t *tmplt_in;

/**
 * \brief Output unirec template.
 */
extern ur_template_t *tmplt_out;

/**
 * \brief Input unirec record.
 */
extern const void *rec_in;

/**
 * \brief Output unirec record.
 */
extern void *rec_out;

/**
 * \brief Current state of the module.
 */
extern module_state_t module_state;

#endif /* LUAMODULE_MODULE_H */
