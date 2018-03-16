//
// Created by slabimic on 24/02/18.
//

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