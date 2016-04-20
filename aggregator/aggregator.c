/**
 * \file aggregator.c
 * \brief Module to filter and agregate flows to gather useful statistics
 * \author Miroslav Kalina <kalinmi2@fit.cvut.cz>
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

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
//#include <stdio.h>
#include <stdint.h>
//#include <stdlib.h>
#include <getopt.h>
#include <time.h> // debug time print
#include <errno.h>
#include <unistd.h>
#include <inttypes.h> // printinf uint32_t / uint64_t
#include <ctype.h> // toupper()
#include <nemea-common.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <unirec/ur_time.h>
#include "fields.h"
#include <liburfilter.h>

#include "aggregator.h"

#define MAX_OUTPUT_COUNT 32
#define MAX_RULES_COUNT 32

/* error handling macros */
#define HANDLE_PERROR(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while(0)
#define HANDLE_ERROR(msg) \
    do { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); } while (0)

UR_FIELDS(
   uint32 PACKETS, //Number of packets in a flow or in an interval
   uint64 BYTES, //Number of bytes in a flow or in an interval
   time TIME_FIRST,
   time TIME_LAST,
)

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("Flow agregation module","Module can be used to filter and agregate flows to gather useful statistics.",1,-1)

#define MODULE_PARAMS(PARAM) \
   PARAM('t', "output_interval", "Time interval in seconds when output is generated. Default: 60 seconds.", required_argument, "int32") \
   PARAM('d', "delay_interval", "Output is delayed by given time interval (sec). This value is necessary and should match active timeout at flow gathering (e.g. flow_meter module) plus 30 seconds. Some flows will be missed if value is too small.", required_argument, "int32") \
   PARAM('I', "inactive_timeout", "When incoming flow is older then inactive timeout, all counters are trashed and reinitialized (module soft restart). Default: 900 seconds.", required_argument, "int32") \
   PARAM('r', "rule", "Filtering and aggregation rule in format NAME:AGGREGATION[:FILTER]. Can be used multiple times", required_argument, "string") \
   PARAM('R', "next_interface", "Step to next output interface.", no_argument, "none") \


/* ************************************************************************* */

static int stop = 0;

static output_t ** outputs = NULL;
static int outputs_count = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);


int flush_aggregation_counters()
{
   static unsigned int header_printed_before = INTMAX_MAX & 0xffffffff;
   int ret;

   // print headers
   if (header_printed_before > 20) {
      header_printed_before = 0;

      printf("--------------------------------------------------------------------------------\n");
      for (int i = 0; i < outputs_count; i++) {
         printf("[OUT-%02d] ", i);
         for (int j = 0; j < outputs[i]->rules_count; j++) {
            if (j > 0) {
               printf(",");
            }
            printf("%s", outputs[i]->rules[j]->name);
         }
         printf("\n");
      }
      printf("--------------------------------------------------------------------------------\n");
   }
   header_printed_before++;

   // print values
   for (int i = 0; i < outputs_count; i++) {
      char buff[20];
      time_t time;
      uint64_t sum;
      uint32_t count;
      int field_id;
      for (int j = 0; j < outputs[i]->rules_count; j++) {
         // get stats and roll old data
         timedb_roll_db(outputs[i]->rules[j]->timedb, &time, &sum, &count);
         
         // time header
         if (j==0) {
            // UniRec
            field_id = ur_get_id_by_name("TIME");
            (* (ur_time_t *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = ur_time_from_sec_msec(time, 0);
//            ur_set(outputs[i]->tpl, outputs[i]->out_rec, field_id, ur_time_from_sec_msec(time, 0));

            // Verbose
            strftime(buff, 20, "%Y-%m-%d %H:%M:%S", gmtime(&time));
            printf("[OUT-%02d] %s", i, buff);
         }
         
         printf(",");

         double avgtmp;
         switch (outputs[i]->rules[j]->agg) {
            case AGG_SUM:
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (* (uint64_t *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = sum;
//               ur_set(outputs[i]->tpl, outputs[i]->out_rec, field_id, sum);
               // Verbose
               printf("%" PRIu64, sum);
               break;
            case AGG_COUNT:
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (* (uint64_t *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = count;
//               ur_set(outputs[i]->tpl, outputs[i]->out_rec, ur_get_id_by_name(outputs[i]->rules[j]->name), count);
               // Verbose
               printf("%" PRIu32, count);
               break;
            case AGG_AVG:
               avgtmp = count>0 ? 1.0*sum/count : 0;
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (* (double *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = avgtmp;
//               ur_set(outputs[i]->tpl, outputs[i]->out_rec, ur_get_id_by_name(outputs[i]->rules[j]->name), avgtmp);
               // Verbose
               printf("%.2f", avgtmp);
               break;
            case AGG_RATE:
               avgtmp = count>0 ? 1.0*sum/outputs[i]->rules[j]->timedb->step : 0;
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (* (double *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = avgtmp;
//               ur_set(outputs[i]->tpl, outputs[i]->out_rec, ur_get_id_by_name(outputs[i]->rules[j]->name), avgtmp);
               // Verbose
               printf("%.2f", avgtmp);
               break;
            default:
               printf("?");
               break;
         }
      }
      printf("\n");
      
      // Send UniRec record
      ret = trap_send(i, outputs[i]->out_rec, ur_rec_fixlen_size(outputs[i]->tpl));
      // Handle possible errors
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
   }

   return 0;
}

rule_t * create_aggregation_rule(const char * specifier, int step, int size, int inactive_timeout)
{
   // @TODO - NAME:AGGREGATION[:FILTER]
   int token_start = 0;

   char * name = NULL;
   char * agg = NULL;
   char * filter = NULL;

   // @TODO použít strtok()

   for (int i = 0; i <= strlen(specifier); i++) {
      // Separator or NULL byte ... token should be processed
      if (specifier[i] == ':' || specifier[i] == 0) {
         // parsing error (null string)
         if (i == token_start && (name != NULL && agg != NULL && filter == NULL)) {
            fprintf(stderr, "Syntax error at char %d: Aggregation rule contains NULL token.\n", i + 1);
            fprintf(stderr, "Rule: :%s\n", specifier);
            for (int j = 0; j <= i + 6; j++)
               fprintf(stderr, " ");
            fprintf(stderr, "^");
            return NULL;
         }

         //@TODO trim whitespaces

         // we just collected name
         if (name == NULL) {
            name = (char *) calloc(i - token_start + 1, sizeof (char));
            strncpy(name, specifier + token_start, i - token_start);
         }
            // or we collected agg type
         else if (agg == NULL) {
            agg = (char *) calloc(i - token_start + 1, sizeof (char));
            strncpy(agg, specifier + token_start, i - token_start);
            for (char * s = agg; *s; ++s) *s = toupper(*s);
         }
            // or filter
         else if (filter == NULL) {
            filter = (char *) calloc(i - token_start + 1, sizeof (char));
            strncpy(filter, specifier + token_start, i - token_start);
         }
         // otherwise parsing error (extra colon found)
         else {
            fprintf(stderr, "Syntax error at char %d: Aggregation rule contains unexpected colon\n", i + 1);
            fprintf(stderr, "Rule: :%s\n", specifier);
            for (int j = 0; j <= i + 5; j++)
               fprintf(stderr, " ");
            fprintf(stderr, "^");
            return NULL;
         }

         token_start = i + 1;
      }
   }

   rule_t * object = (rule_t *) calloc(1, sizeof (rule_t));
   object->name = name;
   object->timedb = timedb_create(step, size, inactive_timeout);

   if (!strcmp(agg, "SUM")) {
      object->agg = AGG_SUM;
   }
   else if (!strcmp(agg, "COUNT")) {
      object->agg = AGG_COUNT;
   }
   else if (!strcmp(agg, "AVG")) {
      object->agg = AGG_AVG;
   }
   else if (!strcmp(agg, "RATE")) {
      object->agg = AGG_RATE;
   }
   else {
      fprintf(stderr, "Error: Unknown aggregation function '%s'\n", agg);
      fprintf(stderr, "Rule: :%s\n", specifier);
      return NULL;
   }

   // @TODO parse also aggregation argument
   object->agg_arg = AGG_ARG_BYTES;

   object->filter = urfilter_prepare(filter);

   //free(name);
   free(agg);
   free(filter);

   return object;
}

void compile_aggregation_rule(rule_t * object)
{
   if (object && object->filter) {
      urfilter_compile_prepared(object->filter);
   }
}

void destroy_aggregation_rule(rule_t * object)
{
   if (object) {
      free(object->name);
      urfilter_destroy(object->filter);
   }
   free(object);
}

// save data from record into time series
int aggregation_rule_save_data(rule_t * rule, ur_template_t * tpl, const void * record)
{
   // get requested value from record
   uint64_t value;
   
   // @TODO replace this for extracting any kind of value
   if (rule->agg_arg == AGG_ARG_BYTES) {
      value = ur_get(tpl, record, F_BYTES);
   }
   else if (rule->agg_arg == AGG_ARG_PACKETS) {
      value = ur_get(tpl, record, F_PACKETS);
   }
   else {
      fprintf(stderr, "Error: This couldn't happen EVER!!! Unknown aggregation target durning main loop.\n");
      return 0;
   }

   // add flow to time series
   switch (rule->agg) {
      // increse sum/count counters
      case AGG_SUM:
      case AGG_COUNT:
      case AGG_AVG:
      case AGG_RATE:
         while(timedb_save_data(rule->timedb, ur_get(tpl, record, F_TIME_FIRST), ur_get(tpl, record, F_TIME_LAST), value) == TIMEDB_SAVE_NEED_ROLLOUT) {
            flush_aggregation_counters();
         }
         break;
      // set flag in hash map (or similar structure)
//      case AGG_COUNT_UNIQ:
//          break;
      default:
         fprintf(stderr, "Error: This couldn't happen EVER!!! Unknown aggregation type durning main loop.\n");
         return 0;
   }
   
   return 1;
}

output_t * create_output(int interface)
{
   output_t * object = calloc(1, sizeof (output_t));

   object->interface = interface;
   object->rules = (rule_t **) calloc(MAX_RULES_COUNT, sizeof (rule_t *));
   if (!object->rules) {
      free(object);
      return NULL;
   }
   object->rules_count = 0;

   return object;
}

void destroy_output(output_t *object)
{
   for (int i = 0; i < object->rules_count; i++) {
      destroy_aggregation_rule(object->rules[i]);
   }
   free(object);
}

int main(int argc, char **argv)
{
   int ret;
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // ***** TRAP initialization *****
   // nelze pouzit default initialization, protoze pocet vystupu neni znamy pri
   // kompilaci ... tzn. nelze ho napsat do MODULE_BASIC_INFO
   //TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   // parse TRAP params
   trap_ifc_spec_t ifc_spec;
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(module_info);
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   // prepare first output interface
   outputs = (output_t **) calloc(MAX_OUTPUT_COUNT, sizeof (output_t *));
   outputs[outputs_count] = create_output(outputs_count);
   outputs_count++;

   // parameters default values
   int param_inactive_timeout = 900;
   int param_output_interval = 60;
   int param_delay_interval = 420;
   
   // parse parameters
   char opt;
   rule_t * temp_rule = NULL;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
            // output_interval
         case 't':
            param_output_interval = atoi(optarg);
            break;
         case 'd':
            param_delay_interval = atoi(optarg);
            break;
         case 'I':
            param_inactive_timeout = atoi(optarg);
            break;
            // rule NAME:AGGREGATION[:FILTER]]
         case 'r':
            temp_rule = create_aggregation_rule(optarg, param_output_interval, param_delay_interval, param_inactive_timeout);
            if (!temp_rule) {
               TRAP_DEFAULT_FINALIZATION();
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
               exit(6);
            }

            outputs[outputs_count - 1]->rules[outputs[outputs_count - 1]->rules_count++] = temp_rule;
            temp_rule = NULL;
            break;
            // switch to another output interface
            // @TODO consider another way of multi interface definition
         case 'R':
            outputs[outputs_count] = create_output(outputs_count);
            outputs_count++;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return 3;
      }
   }

   // set number of output interfaces
   module_info->num_ifc_out = outputs_count;
   
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      trap_free_ifc_spec(ifc_spec);
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }
   
   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER(); // Handles SIGTERM and SIGINT

   // ***** Create UniRec template *****
   char * unirec_specifier = "PACKETS,BYTES";
   
   // initialize input templates
   ur_template_t *tpl = ur_create_input_template(0, unirec_specifier, NULL);
   if (tpl == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return 4;
   }
   
   // Initialize output interfaces and templates
   printf("Output interfaces: %d\n", outputs_count);
   for (int i=0; i<outputs_count; i++) {
      // count tpl_string length
      int tpl_string_len = strlen("time TIME,");
      for (int j=0; j<outputs[i]->rules_count; j++) {
         switch(outputs[i]->rules[j]->agg) {
            // counters, uint64
            case AGG_SUM:
            case AGG_COUNT:
            case AGG_COUNT_UNIQ:
               tpl_string_len += strlen("uint64 ");
               break;
            // averages, double
            case AGG_AVG:
            case AGG_RATE:
               tpl_string_len += strlen("double ");
               break;
         }
         
         tpl_string_len += strlen(outputs[i]->rules[j]->name)+1;
      }
      
      // allocate string
      char *tpl_string = (char *) calloc(tpl_string_len, sizeof(char));
      
      // assemble string
      strcpy(tpl_string, "time TIME");
      int tpl_string_i = strlen("time TIME");
      for (int j=0; j<outputs[i]->rules_count; j++) {
         switch(outputs[i]->rules[j]->agg) {
            // counters, uint64
            case AGG_SUM:
            case AGG_COUNT:
            case AGG_COUNT_UNIQ:
               strcpy(tpl_string+tpl_string_i, ",uint64 ");
               tpl_string_i += strlen(",uint64 ");
               break;
            // averages, double
            case AGG_AVG:
            case AGG_RATE:
               strcpy(tpl_string+tpl_string_i, ",double ");
               tpl_string_i += strlen(",double ");
               break;
         }
         
         strcpy(tpl_string+tpl_string_i, outputs[i]->rules[j]->name);
         tpl_string_i += strlen(outputs[i]->rules[j]->name);
      }
      
      printf("Defining fields (%d, %d) = %s\n", tpl_string_len, (int)strlen(tpl_string), tpl_string);
      
      if (ur_define_set_of_fields(tpl_string) != UR_OK) {
         fprintf(stderr, "Error with creating output template\n");
         return -2;
      }
      char *f_names = ur_ifc_data_fmt_to_field_names(tpl_string);

      printf("Creating template(%d) = %s\n", (int)strlen(f_names), f_names);

      outputs[i]->tpl = ur_create_output_template(i, f_names, NULL);
      
      // Allocate memory for output record
      outputs[i]->out_rec = ur_create_record(outputs[i]->tpl, 0);
      if (outputs[i]->out_rec == NULL){
         fprintf(stderr, "Error: Memory allocation problem (output record).\n");
         exit(EXIT_FAILURE);
      }

      free(f_names);
      free(tpl_string);
   }

   const void *data;
   uint16_t data_size;

   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from input interface (block until data are available)
      ret = TRAP_RECEIVE(0, data, data_size, tpl);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      // Check for end-of-stream message
      if (data_size <= 1) {
         break;
      }

      // process every output
      for (int o = 0; o < outputs_count; o++) {
         // process every rule in output
         for (int i = 0; i < outputs[o]->rules_count; i++) {
            // match UniRec filter
            if (urfilter_match(outputs[o]->rules[i]->filter, tpl, data)) {
               // save record data
               if (!aggregation_rule_save_data(outputs[o]->rules[i], tpl, data)) {
                  fprintf(stderr, "Error when saving aggregationn data.\n");
                  TRAP_DEFAULT_FINALIZATION();
                  FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                  return 6;
               }
            }
         }
      }
   }

   // ***** Cleanup *****

   // clear outputs structure
   for (int i = 0; i < outputs_count; i++) {
      destroy_output(outputs[i]);
   }
   free(outputs);

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_finalize();
   ur_free_template(tpl);
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return EXIT_SUCCESS;
}
