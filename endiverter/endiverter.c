/**
 * \file endiverter.c
 * \brief Module for switching endianess of fields in unirec messages.
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2014-2015 CESNET
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

#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <arpa/inet.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <fields.h>

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Endianness converter", "Switch byte order of fields in unirec messages.", 1, 1)

#define MODULE_PARAMS(PARAM)

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * \brief Swap `size` bytes in memory.
 * \param [in] ptr Pointer to memory
 * \param [in] size Number of bytes to swap.
 */
inline void swap_bytes(char *ptr, size_t size) {
   char a;
   for (int i = 0; i < size / 2; i++) {
      a = ptr[i];
      ptr[i] = ptr[size - i - 1];
      ptr[size - i - 1] = a;
   }
}

int main(int argc, char *argv[])
{
   int ret;
   uint8_t data_fmt = TRAP_FMT_UNKNOWN;
   ur_template_t *tmplt = NULL;

   // ***** TRAP initialization *****
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   trap_set_required_fmt(0, TRAP_FMT_UNIREC, NULL);
   trap_set_data_fmt(0, TRAP_FMT_UNIREC, NULL);

   while (!stop) {
      const void *rec;
      uint16_t rec_size;

      ret = trap_recv(0, &rec, &rec_size);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         const char *spec;

         if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Error: Data format was not loaded.\n");
            break;
         } else {
            tmplt = ur_define_fields_and_update_template(spec, tmplt);
            if (tmplt == NULL) {
               fprintf(stderr, "Error: Template could not be created.\n");
               break;
            }
            trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec);
         }
      } else if (ret != TRAP_E_OK) {
         TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      }

      if (rec_size <= 1) {
         trap_send(0, "", 1);
         break;
      }

      ur_field_id_t id = UR_ITER_BEGIN;
      int i = 0;
      while ((id = ur_iter_fields_record_order(tmplt, i++)) != UR_ITER_END) {
         if (ur_is_present(tmplt, id)) {
            void *ptr = ur_get_ptr_by_id(tmplt, rec, id);

            switch(ur_get_type(id)) {
               case UR_TYPE_TIME:
                  swap_bytes((char *)ptr, sizeof(ur_time_t));
                  break;
               case UR_TYPE_UINT16:
                  swap_bytes((char *)ptr, sizeof(uint16_t));
                  break;
               case UR_TYPE_UINT32:
                  swap_bytes((char *)ptr, sizeof(uint32_t));
                  break;
               case UR_TYPE_UINT64:
                  swap_bytes((char *)ptr, sizeof(uint64_t));
                  break;
               case UR_TYPE_INT16:
                  swap_bytes((char *)ptr, sizeof(int16_t));
                  break;
               case UR_TYPE_INT32:
                  swap_bytes((char *)ptr, sizeof(int32_t));
                  break;
               case UR_TYPE_INT64:
                  swap_bytes((char *)ptr, sizeof(int64_t));
                  break;
               case UR_TYPE_FLOAT:
                  swap_bytes((char *)ptr, sizeof(float));
                  break;
               case UR_TYPE_DOUBLE:
                  swap_bytes((char *)ptr, sizeof(double));
                  break;
               default:
                  break;
            }
         }
      }

      trap_send(0, rec, rec_size);
   }

   if (tmplt != NULL) {
      ur_free_template(tmplt);
   }

   ur_finalize();

   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   return EXIT_SUCCESS;
}
