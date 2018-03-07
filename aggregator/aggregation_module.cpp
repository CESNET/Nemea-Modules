/**
 * \file aggregation_module.cpp
 * \brief Aggregation NEMEA module based on UniRec.
 * \author Michal Slabihoudek <slabimic@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2013,2014,2015,2016 CESNET
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

#include <cstdio>
#include <csignal>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

#include <map>
#include <utility>

#include "output.h"
#include "configuration.h"

trap_module_info_t *module_info = NULL;
/**
 * COUNT, TIME_FIRST, TIME_LAST always used by module
 */
UR_FIELDS (
        uint32 COUNT,
        time TIME_FIRST,
        time TIME_LAST
)

/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Aggregation module", \
        "This module serves for UniRec records aggregation processing. " \
        "User has to specify parameters for processing including key fields and applied aggregation function. " \
        "It receives UniRec and sends UniRec containing the fields which take part in aggregation process. ", 1, 1)

/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
  PARAM('k', "key", "Defines received UniRec field name as part of aggregation key.", required_argument, "string") \
  PARAM('t', "time_window", "[G,A,P]:#seconds. Represents type of timeout and #seconds before sending output.", required_argument, "string") \
  PARAM('s', "sum", "Makes sum of UniRec field values identified by given name.", required_argument, "string") \
  PARAM('a', "avg", "Makes average of UniRec field values identified by given name.", required_argument, "string") \
  PARAM('m', "min", "Keep minimal value of UniRec field identified by given name.", required_argument, "string") \
  PARAM('M', "max", "Keep maximal value of UniRec field identified by given name.", required_argument, "string") \
  PARAM('f', "first", "Keep first value of UniRec field identified by given name.", required_argument, "string") \
  PARAM('l', "last", "Keep first value of UniRec field identified by given name.", required_argument, "string")

/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */


static int stop = 0;


/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

/* ================================================================= */
/* ================== Develop/helper functions ===================== */
/* ================================================================= */

void print_all_defined_ur_fields()
{
   int16_t size = ur_field_specs.ur_last_id;
   for (int i = 0; i < size; i++) {
      const char* name = ur_get_name(i);
      printf("%d. name = %s\n", i, name);
   }
   printf("All data from global unirec structure printed.\n\n");
}
/* ----------------------------------------------------------------- */
void print_template_fields(ur_template_t* tmplt)
{
   int16_t size = tmplt->count;
   for (int i = 0; i < size; i++) {
      const char* name = ur_get_name(tmplt->ids[i]);
      printf("%d. name = %s\n", i, name);
   }
   printf("All data from given template printed.\n\n");
}
/* ----------------------------------------------------------------- */

/* ----------------------------------------------------------------- */
/* ================================================================= */
/* ========================= M A I N =============================== */
/* ================================================================= */
int main(int argc, char **argv)
{
   int ret;
   signed char opt;

   /* **** TRAP initialization **** */

   /*
    * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
    * definitions on the lines 71 and 84 of this file. It also creates a string with short_opt letters for getopt
    * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   /*
    * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /*
    * Register signal handler.
    */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   Config config;
   std::map<Key, void*> storage;

   /*
    * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
    * This macro is defined in config.h file generated by configure script
    */
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'k':
         config.add_member(KEY, optarg);
         break;
      case 't':
         config.set_timeout(optarg);
         break;
      case 's':
         config.add_member(SUM, optarg);
         break;
      case 'a':
         config.add_member(AVG, optarg);
         break;
      case 'm':
         fprintf(stderr, "Develop: Option \'m\' currently being implemented.\n");
         break;
      case 'M':
         fprintf(stderr, "Develop: Option \'M\' currently being implemented.\n");
         break;
      case 'f':
         fprintf(stderr, "Develop: Option \'f\' currently being implemented.\n");
         break;
      case 'l':
         fprintf(stderr, "Develop: Option \'l\' currently being implemented.\n");
         break;
      default:
         fprintf(stderr, "Invalid argument, skipped...\n");
      }
   }

   // DEVEL: print configuration
   config.print();



   /* **** Create UniRec templates **** */
   ur_template_t *in_tmplt = ur_create_input_template(0, "TIME_FIRST,TIME_LAST", NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }

   /* **** Main processing loop **** */

   // Read data from input, process them and write to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

      // Handle possible errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);


      // Check for end-of-stream message
      if (in_rec_size <= 1) {
         continue;
         //break;
      }

      // Change of UniRec input template -> sanity check and templates creation
      if (ret == TRAP_E_FORMAT_CHANGED ) {
         fprintf(stderr, "Format change, setting new module configuration\n");
         // Internal structures cleaning because of possible redefinition
         OutputTemplate::reset();
         KeyTemplate::reset();
         /* todo.. RESET STORED DATA -> FORCE SENDING WHOLE MAP */
         // Only reset map, for testing purposes
         storage.clear();

         //print_all_defined_ur_fields();
         //print_template_fields(in_tmplt);

         int id;
         for (int i = 0; i < config.get_used_fields(); i++) {
            id = ur_get_id_by_name(config.get_name(i));

            if (id == UR_E_INVALID_NAME) {
               fprintf(stderr, "Requested field %s not in input records, cannot continue.\n", config.get_name(i));
               TRAP_DEFAULT_FINALIZATION();
               ur_free_template(in_tmplt);
               ur_finalize();
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               return 1;
            }

            if (config.is_key(i)) {
               KeyTemplate::add_field(id, ur_get_size(id));
            }
            else {
               OutputTemplate::add_field(id, config.get_function_ptr(i, ur_get_type(id)), config.is_func(i, AVG));
            }
         }
         char *tmplt_def = config.return_template_def();
         OutputTemplate::out_tmplt = ur_create_output_template(0, tmplt_def, NULL);
         delete [] tmplt_def;

         if (OutputTemplate::out_tmplt == NULL){
            fprintf(stderr, "Error: Output template could not be created.\n");
            TRAP_DEFAULT_FINALIZATION();
            ur_free_template(in_tmplt);
            ur_finalize();
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            return -1;
         }

         //print_template_fields(OutputTemplate::out_tmplt);

      }

      /* Start message processing */
      time_t record_first = ur_get(in_tmplt, in_rec, F_TIME_FIRST);
      time_t record_last = ur_get(in_tmplt, in_rec, F_TIME_LAST);

      // Generate key
      Key rec_key;
      for (uint i = 0; i < KeyTemplate::used_fields; i++) {
         rec_key.add_field(ur_get_ptr_by_id(in_tmplt, in_rec, KeyTemplate::indexes_to_record[i]),
                           ur_get_size(KeyTemplate::indexes_to_record[i]));
      }

      void *init_ptr = NULL;
      std::pair<std::map<Key, void*>::iterator, bool> inserted;
      inserted = storage.insert(std::make_pair(rec_key, init_ptr));

      if (inserted.second == false) {
         // Element already exists, process the agg function
         printf("Element of given key already exist.\n");
      }
      else {
         // Element inserted, init ur_record and copy fields
         printf("Element of given key inserted.\n");
      }

      //delete rec_key;
   /**
    * Develop purposes end

      TRAP_DEFAULT_FINALIZATION();
      ur_free_template(in_tmplt);
      if (OutputTemplate::out_tmplt)
         ur_free_template(OutputTemplate::out_tmplt);
      ur_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 0;

    * Develop purposes end
   */
   /*
      ur_template_t *out_tmplt = NULL; // DO NOT USE, just there because of exampleModule source bellow
      // Allocate memory for output record
      void *out_rec = ur_create_record(out_tmplt, 0);
      if (out_rec == NULL){
         ur_free_template(in_tmplt);
         ur_free_template(out_tmplt);
         fprintf(stderr, "Error: Memory allocation problem (output record).\n");
         return -1;
      }

      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA

      // Read FOO and BAR from input record and compute their sum
      uint32_t baz = ur_get(in_tmplt, in_rec, F_COUNT) +
                     ur_get(in_tmplt, in_rec, F_COUNT);

      // Fill output record
      ur_copy_fields(out_tmplt, out_rec, in_tmplt, in_rec);
      ur_set(out_tmplt, out_rec, F_COUNT, mult * baz);

      // Send record to interface 0.
      // Block if ifc is not ready (unless a timeout is set using trap_ifcctl)
      ret = trap_send(0, out_rec, ur_rec_fixlen_size(out_tmplt));

      // Handle possible errors
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
   */
   }


   /* **** Cleanup **** */

   // Do all necessary cleanup in libtrap before exiting
   TRAP_DEFAULT_FINALIZATION();

   // Release allocated memory for module_info structure
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // Free unirec templates and output record
   //ur_free_record(out_rec);
   ur_free_template(in_tmplt);
   if (OutputTemplate::out_tmplt) {
      ur_free_template(OutputTemplate::out_tmplt);
   }
   ur_finalize();


   return 0;
}

