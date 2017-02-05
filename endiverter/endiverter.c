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

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <arpa/inet.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <fields.h>

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("endiverter", "Switch byte order of fields in unirec messages.", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('n', "no_eof", "Don't forward EOF message.", no_argument, "none")

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * \brief Swap `size` bytes in memory pointed by `ptr`.
 * \param [in] ptr Pointer to memory.
 * \param [in] size Number of bytes to swap.
 */
static inline void swap_bytes(char *ptr, size_t size) {
   for (int i = 0; i < size / 2; i++) {
      char a = ptr[i];
      ptr[i] = ptr[size - i - 1];
      ptr[size - i - 1] = a;
   }
}

int main(int argc, char *argv[])
{
   int ret, module_status = 0, eof = 1; /* eof - send EOF message on exit. */
   uint8_t data_fmt = TRAP_FMT_UNKNOWN;
   ur_template_t *tmplt = NULL; /* Template storage for input / output ifc. */

   /* TRAP initialization. */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   /* Unset data format on input and output interface. */
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, NULL);

   /* Parse parameters. */
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'n':
         eof = 0;
         break;
      default:
         fprintf(stderr, "endiverter: Error: invalid arguments\n");
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         return 1;
      }
   }

   /* Main loop. */
   while (!stop) {
      const void *rec;
      uint16_t rec_size;

      /* Receive message. */
      ret = trap_recv(0, &rec, &rec_size);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         const char *spec;

         /* Get new data format used on input interface. */
         if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "endiverter: Error: data format was not loaded\n");
            module_status = 1;
            break;
         } else {
            /* Update input / output template. */
            tmplt = ur_define_fields_and_update_template(spec, tmplt);
            if (tmplt == NULL) {
               fprintf(stderr, "endiverter: Error: template could not be created\n");
               module_status = 1;
               break;
            }
            /* Set new data format for output interface. */
            trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec);
         }
      } else if (ret != TRAP_E_OK) {
         TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, module_status = 1; break);
      }

      /* Check for null record. */
      if (rec_size <= 1) {
         /* Forward null record to output interface. */
         if (eof) {
            trap_send(0, "", 1);
         }
         break;
      }


      /* Iterate fields in received unirec message. */
      ur_field_id_t id = UR_ITER_BEGIN;
      int i = 0;
      while ((id = ur_iter_fields_record_order(tmplt, i++)) != UR_ITER_END) {
         if (ur_is_present(tmplt, id)) {
            /* Get pointer to currently processed field. */
            void *ptr = ur_get_ptr_by_id(tmplt, rec, id);

            /* Switch byte order for specific fields. */
            switch(ur_get_type(id)) {
               case UR_TYPE_TIME:
                  swap_bytes((char *) ptr, sizeof(ur_time_t));
                  break;
               case UR_TYPE_UINT16:
                  swap_bytes((char *) ptr, sizeof(uint16_t));
                  break;
               case UR_TYPE_UINT32:
                  swap_bytes((char *) ptr, sizeof(uint32_t));
                  break;
               case UR_TYPE_UINT64:
                  swap_bytes((char *) ptr, sizeof(uint64_t));
                  break;
               case UR_TYPE_INT16:
                  swap_bytes((char *) ptr, sizeof(int16_t));
                  break;
               case UR_TYPE_INT32:
                  swap_bytes((char *) ptr, sizeof(int32_t));
                  break;
               case UR_TYPE_INT64:
                  swap_bytes((char *) ptr, sizeof(int64_t));
                  break;
               case UR_TYPE_STRING:
               case UR_TYPE_BYTES:
                  /* Switch metadata byteorder:
                   * Swap field offset bytes. */
                  swap_bytes(((char *) rec + tmplt->offset[id]), sizeof(uint16_t));
                  /* Swap field length bytes. */
                  swap_bytes(((char *) rec + tmplt->offset[id] + 2), sizeof(uint16_t));
                  break;
               case UR_TYPE_FLOAT:
                  swap_bytes((char *) ptr, sizeof(float));
                  break;
               case UR_TYPE_DOUBLE:
                  swap_bytes((char *) ptr, sizeof(double));
                  break;
               default:
                  break;
            }
         }
      }

      /* Send altered message to output interface. */
      trap_send(0, rec, rec_size);
   }

   /* Cleanup. */
   if (tmplt != NULL) {
      ur_free_template(tmplt);
   }
   ur_finalize();

   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   return module_status;
}
