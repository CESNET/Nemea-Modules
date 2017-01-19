/**
 * \file nfwriter.c
 * \brief nfwriter module read flows from input ifc and saves the them in nfdump file.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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

#include <signal.h>
#include <stdio.h>
#include <getopt.h>

#include <libnf.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "fields.h"

#define BASIC_FLOW_TEMPLATE "DST_IP,SRC_IP,BYTES,LINK_BIT_FIELD,TIME_FIRST,TIME_LAST,PACKETS,DST_PORT,SRC_PORT,DIR_BIT_FIELD,PROTOCOL,TCP_FLAGS,TOS,TTL"

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint8 TOS,
   uint8 TTL
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("nfwriter" ,"This module write flows from input ifc to file in nfdump format.", 1, 0)

#define MODULE_PARAMS(PARAM) \
   PARAM('f', "file", "Output nfdump file.", required_argument, "string") \
   PARAM('a', "append", "Append output to file.", no_argument, "none") \
   PARAM('b', "bz2", "Compress with bz2.", no_argument, "none") \
   PARAM('l', "lzo", "Compress with lzo.", no_argument, "none")

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

int main(int argc, char **argv)
{
   int ret, compress_method = 0, append = 0, module_status = 0;
   uint16_t ur_rec_size;
   uint32_t ipaddr_tmp[4];
   uint64_t flows = 0, tmp;
   const void *ur_rec;
   ur_template_t *tmplt = NULL;
   char *error = NULL, *filename = NULL;

   /* TRAP initialization. */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'f':
         filename = optarg;
         break;
      case 'a':
         append = LNF_APPEND;
         break;
      case 'b':
         compress_method = LNF_COMP_BZ2;
         break;
      case 'l':
         compress_method = LNF_COMP_LZO;
         break;
      default:
         fprintf(stderr, "nfwriter: Error: invalid arguments\n");
         module_status = 1;
         goto exit;
      }
   }

   /* Check if filename was specified. */
   if (filename == NULL) {
      fprintf(stderr, "nfwriter: Error: specify output file with -f param\n");
      module_status = 1;
      goto exit;
   }

   /* Create unirec template. */
   tmplt = ur_create_input_template(0, BASIC_FLOW_TEMPLATE, &error);
   if (tmplt == NULL) {
      fprintf(stderr, "nfwriter: Error: %s\n", error);
      free(error);
      module_status = 1;
      goto exit;
   }

   /* Open file. */
   lnf_file_t *file = NULL;
   if (lnf_open(&file, filename, LNF_WRITE | compress_method | append, NULL) != LNF_OK) {
      fprintf(stderr, "nfwriter: Error: unable to open file \"%s\" for writing\n", filename);
      module_status = 1;
      goto exit;
   }

   /* Create nf record. */
   lnf_rec_t *rec = NULL;
   if (lnf_rec_init(&rec) != LNF_OK) {
      fprintf(stderr, "nfwriter: Error: unable to create lnf record\n");
      lnf_close(file);
      module_status = 1;
      goto exit;
   }
   lnf_rec_clear(rec);

   /* Init array for storing IPv4 addr. */
   ipaddr_tmp[0] = 0;
   ipaddr_tmp[1] = 0;
   ipaddr_tmp[2] = 0;

   /* Main loop. */
   while (!stop) {

      /* Receive message. */
      ret = trap_recv(0, &ur_rec, &ur_rec_size);
      if (ret != TRAP_E_OK) {
         TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, module_status = 1; break);
      }

      /* Check for null record. */
      if (ur_rec_size <= 1) {
         break;
      }

      /* Process IP addresses. */
      ip_addr_t *srcip_ptr = ur_get_ptr(tmplt, ur_rec, F_SRC_IP);
      ip_addr_t *dstip_ptr = ur_get_ptr(tmplt, ur_rec, F_DST_IP);
      if (ip_is4(srcip_ptr)) {
         /* Process IPv4 addr. */
         ipaddr_tmp[3] = htonl(ip_get_v4_as_int(srcip_ptr));
         lnf_rec_fset(rec, LNF_FLD_SRCADDR, ipaddr_tmp);
         ipaddr_tmp[3] = htonl(ip_get_v4_as_int(dstip_ptr));
         lnf_rec_fset(rec, LNF_FLD_DSTADDR, ipaddr_tmp);
      } else {
         /* Process IPv6 addr. */
         lnf_rec_fset(rec, LNF_FLD_SRCADDR, srcip_ptr->ui32);
         lnf_rec_fset(rec, LNF_FLD_DSTADDR, dstip_ptr->ui32);
      }

      /* Process timestamps. */
      tmp = ur_get(tmplt, ur_rec, F_TIME_FIRST);
      tmp = (uint64_t) ur_time_get_sec(tmp) * 1000 + ur_time_get_msec(tmp);
      lnf_rec_fset(rec, LNF_FLD_FIRST, &tmp);

      tmp = ur_get(tmplt, ur_rec, F_TIME_LAST);
      tmp = (uint64_t) ur_time_get_sec(tmp) * 1000 + ur_time_get_msec(tmp);
      lnf_rec_fset(rec, LNF_FLD_LAST, &tmp);

      /* Process other fields. */
      tmp = ur_get(tmplt, ur_rec, F_PACKETS);
      lnf_rec_fset(rec, LNF_FLD_DPKTS, &tmp);
      lnf_rec_fset(rec, LNF_FLD_DOCTETS, ur_get_ptr(tmplt, ur_rec, F_BYTES));
      uint8_t link_bit_fld = ur_get(tmplt, ur_rec, F_LINK_BIT_FIELD);
      lnf_rec_fset(rec, LNF_FLD_ENGINE_ID, &link_bit_fld);
      lnf_rec_fset(rec, LNF_FLD_SRCPORT, ur_get_ptr(tmplt, ur_rec, F_SRC_PORT));
      lnf_rec_fset(rec, LNF_FLD_DSTPORT, ur_get_ptr(tmplt, ur_rec, F_DST_PORT));
      lnf_rec_fset(rec, LNF_FLD_DIR, ur_get_ptr(tmplt, ur_rec, F_DIR_BIT_FIELD));
      lnf_rec_fset(rec, LNF_FLD_PROT, ur_get_ptr(tmplt, ur_rec, F_PROTOCOL));
      lnf_rec_fset(rec, LNF_FLD_TCP_FLAGS, ur_get_ptr(tmplt, ur_rec, F_TCP_FLAGS));
      lnf_rec_fset(rec, LNF_FLD_TOS, ur_get_ptr(tmplt, ur_rec, F_TOS));

      tmp = 1;
      lnf_rec_fset(rec, LNF_FLD_AGGR_FLOWS, &tmp);

      /* Write record to file. */
      if (lnf_write(file, rec) != LNF_OK) {
         fprintf(stderr, "nfwriter: Error: unable to write flow to file\n");
         module_status = 1;
         break;
      }

      flows++;
   }

   if (module_status == 0) {
      printf("nfwriter: %lu flows written to file\n", flows);
   }

   /* Cleanup. */
   lnf_rec_free(rec);
   lnf_close(file);

exit:
   if (tmplt != NULL) {
      ur_free_template(tmplt);
   }

   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
   TRAP_DEFAULT_FINALIZATION();

   return module_status;
}
