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
   time TIME_FIRST,
   time TIME_LAST
)

   // Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("Flow agregation module","Module can be used to filter and agregate flows to gather useful statistics.",1,-1)

#define MODULE_PARAMS(PARAM) \
   PARAM('t', "output_interval", "Time interval in seconds when output is generated. Default: 60 seconds.", required_argument, "int32") \
   PARAM('d', "delay_interval", "Output is delayed by given time interval (sec). This value is necessary and should match active timeout at flow gathering (e.g. flow_meter module) plus 30 seconds. Some flows will be missed if value is too small.", required_argument, "int32") \
   PARAM('I', "inactive_timeout", "When incoming flow is older then inactive timeout, all counters are trashed and reinitialized (module soft restart). Default: 900 seconds.", required_argument, "int32") \
   PARAM('r', "rule", "Filtering and aggregation rule in format NAME:AGGREGATION[:FILTER]. Can be used multiple times. All whitespaces are TRIMMED and you can escape colons with backslash.", required_argument, "string") \
   PARAM('R', "next_interface", "Step to next output interface.", no_argument, "none") \

#define BETWEEN_EQ(value, min, max) (min <= value && value <= max)

/* ************************************************************************* */

static int stop = 0;
// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

static output_t **outputs = NULL;
static int outputs_count = 0;

/* ***** HELPER FUNCTIONS ************************************************** */

void print_syntax_error_position(int position) {
   for (int j = 0; j <= position - 1; j++) {
      fprintf(stderr, " ");
   }
   fprintf(stderr, "^");
}

char *strncpy_no_whitespaces(char *dst, const char *src, int count) {
   int offset = 0;
   int writer = 0;

   for (int j = 0; j + offset < count; j++) {
      // skip whitespaces
      while (isspace(*(src + j + offset))) {
         offset++;
      }

      // detect src+count overflow
      if (j + offset >= count) {
         break;
      }

      // skip backslash in escaped colon
      if (*(src + j + offset) == '\\' && j + offset + 1 < count && *(src + j + offset + 1) == ':') {
         offset++;
      }

      // save dst
      *(dst + (writer++)) = *(src + j + offset);
   }

   return dst;
}

/* ***** OUTPUT HANDLING *************************************************** */

output_t *create_output(int interface)
{
   output_t *object = (output_t *) calloc(1, sizeof(output_t));
   if (!object) {
      return NULL;
   }

   object->interface = interface;
   object->rules = (rule_t **) calloc(MAX_RULES_COUNT, sizeof(rule_t *));
   if (!object->rules) {
      free(object);
      return NULL;
   }

   object->rules_count = 0;
   return object;
}

void destroy_output(output_t *object)
{
   if (!object) {
      return;
   }

   for (int i = 0; i < object->rules_count; i++) {
      rule_destroy(object->rules[i]);
   }

   if (object->out_rec) {
      ur_free_record(object->out_rec);
   }

   if (object->tpl) {
      ur_free_template(object->tpl);
   }

   free(object->rules);
   free(object);
}

int output_initialize_template(output_t *object, int ifc) {
   int ret_val = EXIT_FAILURE;
   int tpl_string_i;
   char *tpl_string = NULL;
   char *f_names = NULL;
   // count tpl_string length
   int tpl_string_len = strlen("time TIME,");
   for (int j = 0; j < object->rules_count; j++) {
      switch(object->rules[j]->agg) {
         // counters, uint64
         case AGG_COUNT:
         case AGG_COUNT_UNIQ:
            tpl_string_len += strlen("uint64 ");
            break;
            // averages, double
         case AGG_SUM:
         case AGG_AVG:
         case AGG_RATE:
            tpl_string_len += strlen("double ");
            break;
      }

      tpl_string_len += strlen(object->rules[j]->name) + 1;
   }

   // allocate string
   tpl_string = (char *) calloc(tpl_string_len, sizeof(char));
   if (!tpl_string) {
      fprintf(stderr, "Error: Calloc failed during creation of template string.\n");
      goto cleanup;
   }

   // assemble string
   strcpy(tpl_string, "time TIME");
   tpl_string_i = strlen("time TIME");
   for (int j = 0; j < object->rules_count; j++) {
      switch(object->rules[j]->agg) {
         // counters, uint64
         case AGG_COUNT:
         case AGG_COUNT_UNIQ:
            strcpy(tpl_string + tpl_string_i, ",uint64 ");
            tpl_string_i += strlen(",uint64 ");
            break;
            // averages, double
         case AGG_SUM:
         case AGG_AVG:
         case AGG_RATE:
            strcpy(tpl_string + tpl_string_i, ",double ");
            tpl_string_i += strlen(",double ");
            break;
      }

      strcpy(tpl_string + tpl_string_i, object->rules[j]->name);
      tpl_string_i += strlen(object->rules[j]->name);
   }

   // Define fields to output template
   if (ur_define_set_of_fields(tpl_string) != UR_OK) {
      fprintf(stderr, "Error: Defining template fields failed.\n");
      fprintf(stderr, "tpl_string: %s\n", tpl_string);
      goto cleanup;
   }

   f_names = ur_ifc_data_fmt_to_field_names(tpl_string);
   if (!f_names) {
      fprintf(stderr, "Error: ur_ifc_data_fmt_to_field_names returned NULL.\n");
      goto cleanup;
   }

   // Create output template
   object->tpl = ur_create_output_template(ifc, f_names, NULL);
   if (!object->tpl) {
      fprintf(stderr, "Error: ur_create_output_template returned NULL.\n");
      goto cleanup;
   }

   // Allocate memory for output record
   object->out_rec = ur_create_record(object->tpl, 0);
   if (!object->out_rec){
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      ur_free_template(object->tpl);
      object->tpl = NULL;
      goto cleanup;
   }

   ret_val = EXIT_SUCCESS;

cleanup:
   free(f_names);
   free(tpl_string);

   return ret_val;
}

/* ************************************************************************* */

int flush_aggregation_counters()
{
   static unsigned int header_printed_before = INTMAX_MAX & 0xffffffff;
   int ret;

   if (trap_get_verbose_level() >= 0) {
      // print headers
      if (header_printed_before > 20) {
         header_printed_before = 0;

         printf("--------------------------------------------------------------------------------\n");
         for (int i = 0; i < outputs_count; i++) {
            printf("[OUT-%02d] TIME", i);
            for (int j = 0; j < outputs[i]->rules_count; j++) {
               printf(",%s", outputs[i]->rules[j]->name);
            }
            printf("\n");
         }
         printf("--------------------------------------------------------------------------------\n");
      }
      header_printed_before++;
   }

   // print values
   for (int i = 0; i < outputs_count; i++) {
      char buff[20];
      time_t time;
      double sum;
      uint32_t count;
      int field_id;
      for (int j = 0; j < outputs[i]->rules_count; j++) {
         // get stats and roll old data
         timedb_roll_db(outputs[i]->rules[j]->timedb, &time, &sum, &count);

         // time header
         if (j == 0) {
            // UniRec
            field_id = ur_get_id_by_name("TIME");
            (*(ur_time_t *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = ur_time_from_sec_msec(time, 0);
            // Verbose
            if (trap_get_verbose_level() >= 0) {
               strftime(buff, 20, "%Y-%m-%d %H:%M:%S", gmtime(&time));
               printf("[OUT-%02d] %s", i, buff);
            }
         }

         if (trap_get_verbose_level() >= 0) {
            printf(",");
         }

         double avgtmp;
         switch (outputs[i]->rules[j]->agg) {
            case AGG_SUM:
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (*(double *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = sum;
               // Verbose
               if (trap_get_verbose_level() >= 0) {
                  printf("%.2f", sum);
               }
               break;
            case AGG_COUNT:
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (*(uint64_t *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = count;
               // Verbose
               if (trap_get_verbose_level() >= 0) {
                  printf("%" PRIu32, count);
               }
               break;
            case AGG_AVG:
               avgtmp = count > 0 ? 1.0 * sum / count : 0;
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (*(double *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = avgtmp;
               // Verbose
               if (trap_get_verbose_level() >= 0) {
                  printf("%.2f", avgtmp);
               }
               break;
            case AGG_RATE:
               avgtmp = count > 0 ? 1.0 * sum / outputs[i]->rules[j]->timedb->step : 0;
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (*(double *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = avgtmp;
               // Verbose
               if (trap_get_verbose_level() >= 0) {
                  printf("%.2f", avgtmp);
               }
               break;
            case AGG_COUNT_UNIQ:
               // UniRec
               field_id = ur_get_id_by_name(outputs[i]->rules[j]->name);
               (*(uint64_t *) ur_get_ptr_by_id(outputs[i]->tpl, outputs[i]->out_rec, field_id)) = count;
               // Verbose
               if (trap_get_verbose_level() >= 0) {
                  printf("%" PRIu32, count);
               }
               break;
            default:
               printf("?");
               break;
         }
      }

      if (trap_get_verbose_level() >= 0) {
         printf("\n");
      }

      // Send UniRec record
      ret = trap_send(i, outputs[i]->out_rec, ur_rec_fixlen_size(outputs[i]->tpl));
      // Handle possible errors
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break)
   }

   return 0;
}

int rule_parse_agg_function(const char *specifier, agg_function *function, char **arg) {
   // expected format <function>(<arg>), all whitespaces should be trimmed before
   char *function_str = NULL;
   char *agg_str = NULL;

   if (!specifier) {
      fprintf(stderr, "Error: Passed NULL pointer to rule_parse_agg_function. Possibly no aggregation function specified.\n");
      return 0;
   }

   int token_start = 0;
   for (int i = 0; i < strlen(specifier); i++) {
      if (specifier[i] == '(') {
         if (function_str) {
            fprintf(stderr, "Syntax error: Unexpected opening parenthesis in aggregation function.\n");
            fprintf(stderr, " Aggregation function: %s\n", specifier);
            print_syntax_error_position(i + (int) strlen(" Aggregation function: "));
            free(function_str);
            free(agg_str);
            return 0;
         } else {
            function_str = (char *) calloc(i - token_start + 1, sizeof(char));
            if (!function_str) {
               fprintf(stderr, "Error: Calloc failed during parsing aggregation functions.\n");
               free(agg_str);
               return 0;
            }

            strncpy(function_str, specifier + token_start, i - token_start);
            token_start = i + 1;
         }
      } else if (specifier[i] == ')') {
         if (agg_str) {
            fprintf(stderr, "Syntax error: Unexpected closing parenthesis in aggregation function.\n");
            fprintf(stderr, " Aggregation function: %s\n", specifier);
            print_syntax_error_position(i + (int) strlen(" Aggregation function: "));
            free(function_str);
            free(agg_str);
            return 0;
         } else {
            agg_str = (char *) calloc(i - token_start + 1, sizeof(char));
            if (!agg_str) {
               fprintf(stderr, "Error: Calloc failed during parsing aggregation functions.\n");
               free(function_str);
               return 0;
            }

            strncpy(agg_str, specifier + token_start, i - token_start);
            token_start = i + 1;
         }
      }
   }

   // sanity check - empty function string
   if (!function_str || *function_str == 0) {
      fprintf(stderr, "Syntax error: Unable to parse aggregation function. Perhaps missing parenthesis?\n");
      fprintf(stderr, " Aggregation function: %s\n", specifier);
      free(function_str);
      free(agg_str);
      return 0;
   }

   if (!strcmp(function_str, "SUM")) {
      *function = AGG_SUM;
   } else if (!strcmp(function_str, "COUNT")) {
      *function = AGG_COUNT;
   } else if (!strcmp(function_str, "AVG")) {
      *function = AGG_AVG;
   } else if (!strcmp(function_str, "RATE")) {
      *function = AGG_RATE;
   } else if (!strcmp(function_str, "COUNT_UNIQ")) {
      *function = AGG_COUNT_UNIQ;
   } else {
      fprintf(stderr, "Error: Unknown aggregation function.\n");
      fprintf(stderr, " Function name: %s\n", function_str);
      free(function_str);
      free(agg_str);
      return 0;
   }

   free(function_str);
   *arg = agg_str;
   return 1;
}

rule_t *rule_create(const char *specifier, int step, int size, int inactive_timeout)
{
   // rule format - NAME:AGGREGATION[:FILTER]
   char *name = NULL;
   char *agg = NULL;
   char *filter = NULL;
   rule_t *object = NULL;

   int token_start = 0;
   for (int i = 0; i <= strlen(specifier); i++) {
      // Separator or NULL byte ... token should be processed
      if ((specifier[i] == ':' && (i == 0 || specifier[i - 1] != '\\')) || specifier[i] == 0) {
         // parsing error (null string)
         if (i == token_start && (name != NULL && agg != NULL && filter == NULL)) {
            fprintf(stderr, "Syntax error at char %d: Aggregation rule contains NULL token.\n", i + 1);
            print_syntax_error_position(i + 8);
            goto error_cleanup;
         }

         // we just collected name
         if (name == NULL) {
            name = (char *) calloc(i - token_start + 1, sizeof(char));
            if (!name) {
               fprintf(stderr, "Error: Calloc failed during the creation of aggregation rule.\n");
               goto error_cleanup;
            }

            strncpy_no_whitespaces(name, specifier + token_start, i - token_start);
         } else if (agg == NULL) { // or we collected agg type
            agg = (char *) calloc(i - token_start + 1, sizeof(char));
            if (!agg) {
               fprintf(stderr, "Error: Calloc failed during the creation of aggregation rule.\n");
               goto error_cleanup;
            }

            strncpy_no_whitespaces(agg, specifier + token_start, i - token_start);
            for (char *s = agg; *s; ++s) {
               *s = toupper(*s);
            }
         } else if (filter == NULL) { // or filter
            filter = (char *) calloc(i - token_start + 1, sizeof(char));
            if (filter) {
               fprintf(stderr, "Error: Calloc failed during the creation of aggregation rule.\n");
               goto error_cleanup;
            }

            strncpy_no_whitespaces(filter, specifier + token_start, i - token_start);
         } else { // otherwise parsing error (extra colon found)
            fprintf(stderr, "Syntax error at char %d: Aggregation rule contains unexpected colon\n", i + 1);
            fprintf(stderr, "Rule: :%s\n", specifier);
            for (int j = 0; j <= i + 5; j++) {
               fprintf(stderr, " ");
            }

            fprintf(stderr, "^");
            goto error_cleanup;
         }

         token_start = i + 1;
      }
   }
   // sanity check
   if (!name || *name == 0) {
      fprintf(stderr, "Error: Rule name cannot be empty.");
      fprintf(stderr, "Rule: %s\n", specifier);
      goto error_cleanup;
   }

   // rulename must match regex [A-Za-z][A-Za-z0-9_]*
   for (int i = 0; i < strlen(name); i++) {
      if ((i == 0 && !(BETWEEN_EQ(name[i], 'A', 'Z') || BETWEEN_EQ(name[i], 'a', 'z'))) ||
            (i >= 1 && !(BETWEEN_EQ(name[i], 'A', 'Z') || BETWEEN_EQ(name[i], 'a', 'z') || BETWEEN_EQ(name[i], '0', '9') || name[i] == '_'))) {
         fprintf(stderr, "Error: Rule name contains unexpected characters.\n");
         fprintf(stderr, " Rule name: %s\n", name);
         goto error_cleanup;
      }
   }

   // construct aggregation rule object
   object = (rule_t *) calloc(1, sizeof (rule_t));
   if (!object) {
      fprintf(stderr, "Error: Calloc failed during the creation of aggregation rule.\n");
      goto error_cleanup;
   }

   object->name = name;

   // parse aggregation function
   if (!rule_parse_agg_function(agg, &object->agg, &object->agg_arg)) {
      goto error_cleanup;
   }

   object->timedb = timedb_create(step, size, inactive_timeout, object->agg == AGG_COUNT_UNIQ ? 1 : 0);
   object->filter = urfilter_create(filter, "0");

   free(filter);
   free(agg);
   return object;

error_cleanup:
   free(name);
   free(agg);
   free(filter);
   free(object);
   return NULL;
}

void rule_compile(rule_t *object)
{
   if (object && object->filter) {
      urfilter_compile(object->filter);
   }
}

void rule_destroy(rule_t *object)
{
   if (object) {
      free(object->name);
      free(object->agg_arg);
      urfilter_destroy(object->filter);
      timedb_free(object->timedb);
      free(object);
   }
}

// save data from record into time series
int rule_save_data(rule_t *rule, ur_template_t *tpl, const void *record)
{
   // get argument field_id
   int field_id = ur_get_id_by_name(rule->agg_arg);
   if (field_id == UR_E_INVALID_NAME) {
      fprintf(stderr, "Fatal error: Aggregation argument is not present in UniRec template.\n");
      fprintf(stderr, " Aggregation argument: %s\n", rule->agg_arg);
      return 0;
   }

   ur_field_type_t field_type = ur_get_type(field_id);
   switch(field_type) {
      case UR_TYPE_CHAR:
      case UR_TYPE_INT8:
      case UR_TYPE_INT16:
      case UR_TYPE_INT32:
      case UR_TYPE_INT64:
      case UR_TYPE_UINT8:
      case UR_TYPE_UINT16:
      case UR_TYPE_UINT32:
      case UR_TYPE_UINT64:
      case UR_TYPE_FLOAT:
      case UR_TYPE_DOUBLE:
         break;
      case UR_TYPE_IP:
      case UR_TYPE_MAC:
      case UR_TYPE_TIME:
      case UR_TYPE_STRING:
      case UR_TYPE_BYTES:
         switch(rule->agg) {
            case AGG_SUM:
            case AGG_COUNT:
            case AGG_AVG:
            case AGG_RATE:
               fprintf(stderr, "Error: Only COUNT_UNIQ make sense with IP, MAC, TIME, STRING or BYTES.\n");
               fprintf(stderr, " Aggregation rule name: %s\n", rule->name);
               return 0;
               break;
            default:
               break;
         }
         break;
      default:
         fprintf(stderr, "Error: Unsupported type of aggregation argument.\n");
         fprintf(stderr, " Aggregation rule name: %s\n", rule->name);
         fprintf(stderr, " Aggregation argument name: %s\n", rule->agg_arg);
         return 0;
   }

   // get record pointer
   void *value = ur_get_ptr_by_id(tpl, record, field_id);
   int var_value_size;

   switch(field_type){
      case UR_TYPE_STRING:
      case UR_TYPE_BYTES:
         var_value_size = ur_get_var_len(tpl, record, field_id);
         break;
      default:
         var_value_size = 0;
         break;
   }

   // add flow to time series
   switch (rule->agg) {
      // increse sum/count counters
      case AGG_SUM:
      case AGG_COUNT:
      case AGG_AVG:
      case AGG_RATE:
      case AGG_COUNT_UNIQ:
         while (timedb_save_data(rule->timedb, ur_get(tpl, record, F_TIME_FIRST), ur_get(tpl, record, F_TIME_LAST), field_type, value, var_value_size) == TIMEDB_SAVE_NEED_ROLLOUT) {
            flush_aggregation_counters();
         }
         break;
      default:
         fprintf(stderr, "Error: This couldn't happen EVER!!! Unknown aggregation type durning main loop.\n");
         return 0;
   }

   return 1;
}

int main(int argc, char **argv)
{
   int ret = TRAP_E_OK;          // Variable for storing return values from libtrap
   int ret_val = EXIT_FAILURE;   // Variable for storing return value of this module

   // parameters default values
   int param_inactive_timeout = 900;
   int param_output_interval = 60;
   int param_delay_interval = 420;

   char opt;
   rule_t *temp_rule = NULL;
   ur_template_t *tpl = NULL;

   const void *data;
   uint16_t data_size;
   uint8_t timedb_initialized = 0;

   // ***** TRAP initialization *****
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info)

   // prepare first output interface
   outputs = (output_t **) calloc(MAX_OUTPUT_COUNT, sizeof(output_t *));
   if (!outputs) {
      fprintf(stderr, "Error: Calloc failed during interface initialization.\n");
      goto cleanup;
   }

   outputs[outputs_count] = create_output(outputs_count);
   if (!outputs[outputs_count]) {
      fprintf(stderr, "Error: Calloc failed during interface initialization.\n");
      goto cleanup;
   }

   outputs_count++;

   // parse parameters
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 't':  // output_interval = TimeDB step value
            param_output_interval = atoi(optarg);
            if (param_output_interval < 1) {
               fprintf(stderr, "Error: Passed illogical value to parameter -t: %d.\n", param_output_interval);
               goto cleanup;
            }

            break;
         case 'd':  // TimeDB delay interval
            param_delay_interval = atoi(optarg);
            if (param_delay_interval < 1) {
               fprintf(stderr, "Error: Passed illogical value to parameter -d: %d.\n", param_delay_interval);
               goto cleanup;
            }

            break;
         case 'I':  // Inactive timeout
            param_inactive_timeout = atoi(optarg);
            if (param_inactive_timeout < 1) {
               fprintf(stderr, "Error: Passed illogical value to parameter -I: %d.\n", param_inactive_timeout);
               goto cleanup;
            }

            break;
         case 'r':  // rule syntax NAME:AGGREGATION[:FILTER]]
            temp_rule = rule_create(optarg, param_output_interval, param_delay_interval, param_inactive_timeout);
            if (!temp_rule) {
               goto cleanup;
            }

            outputs[outputs_count - 1]->rules[outputs[outputs_count - 1]->rules_count++] = temp_rule;
            temp_rule = NULL;
            break;
         case 'R':  // switch to another output interface
            // @TODO consider another way of multi interface definition
            outputs[outputs_count] = create_output(outputs_count);
            if (!outputs[outputs_count]) {
               fprintf(stderr, "Error: Calloc failed during interface initialization.\n");
               goto cleanup;
            }

            outputs_count++;
            break;
         default:
            fprintf(stderr, "Error: Invalid arguments.\n");
            goto cleanup;
      }
   }

   // check output interface counts
   if(module_info->num_ifc_out != outputs_count) {
      fprintf(stderr, "Error: Number of TRAP interfaces doesn't match number defined by rules.\n");
      fprintf(stderr, " TRAP output interfaces: %d\n", module_info->num_ifc_out);
      fprintf(stderr, " Configured outputs by rules: %d\n", outputs_count);
      goto cleanup;
   }

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER(); // Handles SIGTERM and SIGINT

   // ***** Create input UniRec template *****
   tpl = ur_create_input_template(0, "TIME_FIRST,TIME_LAST", NULL);
   if (!tpl) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      goto cleanup;
   }

   // ***** Create output UniRec template *****
   for (int i = 0; i < outputs_count; i++) {
      if(output_initialize_template(outputs[i], i) == EXIT_FAILURE) {
         goto cleanup;
      }
   }

   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from input interface (block until data are available)
      ret = TRAP_RECEIVE(0, data, data_size, tpl);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break)

      // Check for end-of-stream message
      if (data_size <= 1) {
         break;
      }

      // Initialize TimeDBs synchronously
      if (!timedb_initialized) {
         time_t time = ur_time_get_sec(ur_get(tpl, data, F_TIME_FIRST));
         for (int o = 0; o < outputs_count; o++) {
            for (int i = 0; i < outputs[o]->rules_count; i++) {
               timedb_init(outputs[o]->rules[i]->timedb, time);
            }
         }
         timedb_initialized = 1;
      }

      // process every output
      for (int o = 0; o < outputs_count; o++) {
         // process every rule in output
         for (int i = 0; i < outputs[o]->rules_count; i++) {
            // match UniRec filter
            if (urfilter_match(outputs[o]->rules[i]->filter, tpl, data)) {
               // save record data
               if (!rule_save_data(outputs[o]->rules[i], tpl, data)) {
                  fprintf(stderr, "Error: Saving aggregation data failed.\n");
                  goto cleanup;
               }
            }
         }
      }
   }

   if (ret == TRAP_E_TERMINATED || ret == TRAP_E_OK) {
      ret_val = EXIT_SUCCESS;
   }

cleanup:
   // ***** Cleanup *****

   TRAP_DEFAULT_FINALIZATION()
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   // clear outputs structure
   for (int i = 0; i < outputs_count; i++) {
      destroy_output(outputs[i]);
   }

   free(outputs);

   ur_finalize();
   ur_free_template(tpl);
   return ret_val;
}
