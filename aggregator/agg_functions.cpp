/**
 * \file agg_functions.cpp
 * \brief Aggregation functions available for use in module.
 * \author Michal Slabihoudek <slabimic@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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

#include "agg_functions.h"
#include "output.h"

/* ================================================================= */
/* ======================= Min function =========================== */
/* ================================================================= */
void min_ip(const void *src, void *dst)
{
   // ret is negative number (<0) if addr1 < addr2
   int ret = ip_cmp((const ip_addr_t*)src, (const ip_addr_t*)dst);

   if (ret < 0)
      *((ip_addr_t*)dst) = *((ip_addr_t*)src);
   // or use memcpy(&dst, src, 16);

}

/* ================================================================= */
/* ======================= Max function =========================== */
/* ================================================================= */
void max_ip(const void *src, void *dst)
{
   // ret is positive number (>0) if addr1 > addr2
   int ret = ip_cmp((const ip_addr_t*)src, (const ip_addr_t*)dst);

   if (ret > 0)
      *((ip_addr_t*)dst) = *((ip_addr_t*)src);
   // or use memcpy(&dst, src, 16);
}

/* ================================================================= */
/* ================== Nope/First function ========================== */
/* ================================================================= */
void nope(const void *src, void *dst)
{
   // DO NOTHING
}

/* ================================================================= */
/* ======================= Last function =========================== */
/* ================================================================= */
void last_variable(const void *src, void *dst)
{
   var_params *params = (var_params*)dst;
   ur_set_var(OutputTemplate::out_tmplt, params->dst, params->field_id, src, params->var_len);
}