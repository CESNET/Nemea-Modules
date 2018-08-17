/**
 * \file configuration.cpp
 * \brief Module running properties configuration.
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

#include <utility>
#include "configuration.h"

Config::Config() : used_fields(0), timeout_type(TIMEOUT_ACTIVE), variable_flag(false)
{
   for (int i = 0; i < TIMEOUT_TYPES_COUNT; i++) {
      timeout[i] = DEFAULT_TIMEOUT;
   }
}


Config::~Config()
{
   for (int i = 0; i < used_fields; i++) {
      delete [] field_names[i];
   }
}

bool Config::verify_field(const char *field_name)
{
   // Time fields cannot be assigned
   if ((strcmp(field_name, "TIME_LAST") == 0) || (strcmp(field_name, "TIME_FIRST") == 0)) {
      return false;
   }

   // Check if already assigned
   for (int i = 0; i < used_fields; i++) {
      if (strcmp(field_name, field_names[i]) == 0)
         return false;
   }
   return true;
}

int Config::get_used_fields()
{
   return used_fields;
}

const char * Config::get_name(int index)
{
   if ((index < 0) || (index > used_fields - 1)) {
      return "";
   }

   return field_names[index];
}

bool Config::is_variable()
{
   return variable_flag;
}

void Config::set_variable(bool flag)
{
   variable_flag = flag;
}

bool Config::is_key(int index)
{
   if ((index < 0) || (index > used_fields - 1)) {
      return false;
   }

   if (functions[index] == KEY) {
      return true;
   }
   return false;
}

bool Config::is_func(int index, int func_id)
{
   if ((index < 0) || (index > used_fields - 1)) {
      return false;
   }

   if (functions[index] == func_id) {
      return true;
   }
   return false;
}

//agg_func Config::get_function_ptr(int index, ur_field_type_t field_type)
std::pair<agg_func, check_func> Config::get_function_ptr(int index, ur_field_type_t field_type)
{
   std::pair<agg_func, check_func> out (&nope, &no_check);

   if ((index < 0) || (index > used_fields - 1)) {
      return out;
   }

   switch (functions[index]) {
      case SUM:
         switch (field_type) {
            case UR_TYPE_INT8:
               out.first = &sum<int8_t>;
               out.second = &check_safe_signed_add<int8_t>;
               break;
            case UR_TYPE_INT16:
               out.first = &sum<int16_t>;
               out.second = &check_safe_signed_add<int16_t>;
               break;
            case UR_TYPE_INT32:
               out.first = &sum<int32_t>;
               out.second = &check_safe_signed_add<int32_t>;
               break;
            case UR_TYPE_INT64:
               out.first = &sum<int64_t>;
               out.second = &check_safe_signed_add<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out.first = &sum<uint8_t>;
               out.second = &check_safe_unsigned_add<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out.first = &sum<uint16_t>;
               out.second = &check_safe_unsigned_add<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out.first = &sum<uint32_t>;
               out.second = &check_safe_unsigned_add<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out.first = &sum<uint64_t>;
               out.second = &check_safe_unsigned_add<uint64_t>;
               break;
            case UR_TYPE_FLOAT:
               out.first = &sum<float>;
               break;
            case UR_TYPE_DOUBLE:
               out.first = &sum<double>;
               break;
            default:
               fprintf(stderr, "Only int, uint, float and double can use sum function, first assigned instead.\n");
               out.first = &nope;
         }
         break;
      case AVG:
         switch (field_type) {
            case UR_TYPE_INT8:
               out.first = &avg<int8_t>;
               break;
            case UR_TYPE_INT16:
               out.first = &avg<int16_t>;
               break;
            case UR_TYPE_INT32:
               out.first = &avg<int32_t>;
               break;
            case UR_TYPE_INT64:
               out.first = &avg<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out.first = &avg<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out.first = &avg<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out.first = &avg<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out.first = &avg<uint64_t>;
               break;
            case UR_TYPE_FLOAT:
               out.first = &avg<float>;
               break;
            case UR_TYPE_DOUBLE:
               out.first = &avg<double>;
               break;
            default:
               fprintf(stderr, "Only int, uint, float and double can use avg function, first assigned instead.\n");
               out.first = &nope;
         }
         break;
      case MIN:
         switch (field_type) {
            case UR_TYPE_INT8:
               out.first = &min<int8_t>;
               break;
            case UR_TYPE_INT16:
               out.first = &min<int16_t>;
               break;
            case UR_TYPE_INT32:
               out.first = &min<int32_t>;
               break;
            case UR_TYPE_INT64:
               out.first = &min<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out.first = &min<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out.first = &min<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out.first = &min<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out.first = &min<uint64_t>;
               break;
            case UR_TYPE_FLOAT:
               out.first = &min<float>;
               break;
            case UR_TYPE_DOUBLE:
               out.first = &min<double>;
               break;
            case UR_TYPE_CHAR:
               out.first = &min<char>;
               break;
            case UR_TYPE_TIME:
               out.first = &min<uint64_t>;
               break;
            case UR_TYPE_IP:
               out.first = &min_ip;
               break;
            default:
               fprintf(stderr, "Only fixed length fields can use min function, first assigned instead.\n");
               out.first = &nope;
         }
         break;
      case MAX:
         switch (field_type) {
            case UR_TYPE_INT8:
               out.first = &max<int8_t>;
               break;
            case UR_TYPE_INT16:
               out.first = &max<int16_t>;
               break;
            case UR_TYPE_INT32:
               out.first = &max<int32_t>;
               break;
            case UR_TYPE_INT64:
               out.first = &max<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out.first = &max<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out.first = &max<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out.first = &max<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out.first = &max<uint64_t>;
               break;
            case UR_TYPE_FLOAT:
               out.first = &max<float>;
               break;
            case UR_TYPE_DOUBLE:
               out.first = &max<double>;
               break;
            case UR_TYPE_CHAR:
               out.first = &max<char>;
               break;
            case UR_TYPE_TIME:
               out.first = &max<uint64_t>;
               break;
            case UR_TYPE_IP:
               out.first = &max_ip;
               break;
            default:
               fprintf(stderr, "Only fixed length fields can use max function, first assigned instead.\n");
               out.first = &nope;
         }
         break;
      case FIRST:
         // Keep nope function because first value is set by copy from input record
         out.first = &nope;
         break;
      case LAST:
         switch (field_type) {
            case UR_TYPE_INT8:
               out.first = &last<int8_t>;
               break;
            case UR_TYPE_INT16:
               out.first = &last<int16_t>;
               break;
            case UR_TYPE_INT32:
               out.first = &last<int32_t>;
               break;
            case UR_TYPE_INT64:
               out.first = &last<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out.first = &last<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out.first = &last<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out.first = &last<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out.first = &last<uint64_t>;
               break;
            case UR_TYPE_FLOAT:
               out.first = &last<float>;
               break;
            case UR_TYPE_DOUBLE:
               out.first = &last<double>;
               break;
            case UR_TYPE_CHAR:
               out.first = &last<char>;
               break;
            case UR_TYPE_TIME:
               out.first = &last<uint64_t>;
               break;
            case UR_TYPE_IP:
               out.first = &last<ip_addr_t>;
               break;
            case UR_TYPE_STRING:
               out.first = &last_variable;
               break;
            case UR_TYPE_BYTES:
               out.first = &last_variable;
               break;
            default:
               fprintf(stderr, "Type is not supported by current version of module, using first instead.\n");
               out.first = &nope;
         }
         break;
      case BIT_OR:
         switch (field_type) {
            case UR_TYPE_INT8:
               out.first = &bitwise_or<int8_t>;
               break;
            case UR_TYPE_INT16:
               out.first = &bitwise_or<int16_t>;
               break;
            case UR_TYPE_INT32:
               out.first = &bitwise_or<int32_t>;
               break;
            case UR_TYPE_INT64:
               out.first = &bitwise_or<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out.first = &bitwise_or<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out.first = &bitwise_or<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out.first = &bitwise_or<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out.first = &bitwise_or<uint64_t>;
               break;
            case UR_TYPE_CHAR:
               out.first = &bitwise_or<char>;
               break;
            default:
               fprintf(stderr, "Only int, uint and char can use bitwise functions, first assigned instead.\n");
               out.first = &nope;
         }
         break;
      case BIT_AND:
         switch (field_type) {
            case UR_TYPE_INT8:
               out.first = &bitwise_and<int8_t>;
               break;
            case UR_TYPE_INT16:
               out.first = &bitwise_and<int16_t>;
               break;
            case UR_TYPE_INT32:
               out.first = &bitwise_and<int32_t>;
               break;
            case UR_TYPE_INT64:
               out.first = &bitwise_and<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out.first = &bitwise_and<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out.first = &bitwise_and<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out.first = &bitwise_and<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out.first = &bitwise_and<uint64_t>;
               break;
            case UR_TYPE_CHAR:
               out.first = &bitwise_and<char>;
               break;
            default:
               fprintf(stderr, "Only int, uint and char can use bitwise functions, first assigned instead.\n");
               out.first = &nope;
         }
         break;
   }
   return out;
}

final_avg Config::get_avg_ptr(int index, ur_field_type_t field_type)
{
   final_avg out = NULL;
   if ((index < 0) || (index > used_fields - 1)) {
      return out;
   }

   switch (functions[index]) {
      case AVG:
         switch (field_type) {
            case UR_TYPE_INT8:
               out = &make_avg<int8_t>;
               break;
            case UR_TYPE_INT16:
               out = &make_avg<int16_t>;
               break;
            case UR_TYPE_INT32:
               out = &make_avg<int32_t>;
               break;
            case UR_TYPE_INT64:
               out = &make_avg<int64_t>;
               break;
            case UR_TYPE_UINT8:
               out = &make_avg<uint8_t>;
               break;
            case UR_TYPE_UINT16:
               out = &make_avg<uint16_t>;
               break;
            case UR_TYPE_UINT32:
               out = &make_avg<uint32_t>;
               break;
            case UR_TYPE_UINT64:
               out = &make_avg<uint64_t>;
               break;
            case UR_TYPE_FLOAT:
               out = &make_avg<float>;
               break;
            case UR_TYPE_DOUBLE:
               out = &make_avg<double>;
               break;
            default:
               out = NULL;
            }
         break;
      default:
         out = NULL;
   }
   return out;
}

/**
 * This function adds field into configuration class of module
 * @param func [in] Identification of function to use as defined MACRO
 * @param field_name [in] string given by user to identify the field
 */
void Config::add_member(int func, const char *field_name)
{
   if (!(used_fields < MAX_KEY_FIELDS)) {
      fprintf(stderr, "Cannot register the field \"%s\", maximum number of assigned fields reached. "
              "Please contact developer to increase the number with use case this happen with.\n", field_name);
      return;
   }

   if (!verify_field(field_name)) {
      fprintf(stderr, "Field \"%s\" already used or cannot be assigned.\n", field_name);
      return;
   }

   int name_length = strlen(field_name);
   field_names[used_fields] = new char [name_length + 1];
   strncpy(field_names[used_fields], field_name, name_length + 1);
   functions[used_fields] = func;
   used_fields++;
}
int Config::get_timeout(int type)
{
   return timeout[type];
}


int Config::get_timeout_type()
{
   return timeout_type;
}

/**
 * This function parses configuration string from user and set the module parameters.
 *
 * @param input [in] Timeout configuration from user
 */
void Config::set_timeout(const char *input)
{
   size_t str_len = strlen(input);
   // Using constant 21 -> max int size 2,147,483,647 => 10 digits => max size is 'int:int'
   if (str_len > 21 ) {
      fprintf(stderr, "Definition string is too long, using default settings.\n");
      return;
   }
   char *definition = new char [str_len + 1];
   strncpy(definition, input, str_len + 1);

   char *first = strtok(definition, ":");
   if(first) {
      // Can be type or #second
      char *second = strtok(NULL, ":");
      if(second) {
         // Now first considered as type definition
         switch (first[0]) {
            case 'a':
            case 'A':
               timeout_type = TIMEOUT_ACTIVE;
               break;
            case 'p':
            case 'P':
               timeout_type = TIMEOUT_PASSIVE;
               break;
            case 'g':
            case 'G':
               timeout_type = TIMEOUT_GLOBAL;
               break;
            case 'm':
            case 'M':
               timeout_type = TIMEOUT_ACTIVE_PASSIVE;
               break;
            default:
               fprintf(stderr, "Unknown timeout type \'%c\', keeping default.\n", first[0]);
         }
         if (timeout_type == TIMEOUT_ACTIVE_PASSIVE) {
            // There need to be 2 times splitted by char ','
            char *active_timeout = strtok(second, ",");
            if (active_timeout) {
               // There allways be something due to second existance
               char *passive_timeout = strtok(NULL, ",");
               if (passive_timeout) {
                  // Now valid time definition
                  timeout[TIMEOUT_ACTIVE] = atoi(active_timeout);
                  timeout[TIMEOUT_PASSIVE] = atoi(passive_timeout);
               }
               else {
                  // Time definition wrong
                  fprintf(stderr, "Wrong timeout type definition \"-t m:Active,Passive\"\n"
                          "Keeping default timeout type.\n");
                  timeout_type = TIMEOUT_ACTIVE;
               }
            }
         }
         else
            timeout[timeout_type] = atoi(second);
      }
      else {
         timeout[timeout_type] = atoi(first);
      }
   }

   if (timeout_type == TIMEOUT_ACTIVE_PASSIVE) {
      if((timeout[TIMEOUT_ACTIVE] <= 0) || (timeout[TIMEOUT_PASSIVE] <= 0)) {
         fprintf(stderr, "Timeout value is not > 0, keeping default value.\n");
         timeout[TIMEOUT_ACTIVE] = DEFAULT_TIMEOUT;
         timeout[TIMEOUT_PASSIVE] = DEFAULT_TIMEOUT;
      }
   }
   else {
      if(timeout[timeout_type] <= 0) {
         fprintf(stderr, "%d is not > 0, keeping default value.\n", timeout[timeout_type]);
         timeout[timeout_type] = DEFAULT_TIMEOUT;
      }
   }

   delete [] definition;
}

/**
 *
 * @return string which defines ur_template from user input, has to be freed manually
 */
char* Config::return_template_def()
{
   const char *static_fields = STATIC_FIELDS;
   size_t len = strlen(static_fields) + 1;
   for (int i = 0; i < used_fields; i++) {
      // +1 for every name -> ',' after every field and \0 at the end
      len += strlen(field_names[i]) + 1;
   }
   char *tmplt_def = new char [len];
   // Because strcat needs to start replacing null terminated string
   tmplt_def[0] = '\0';
   for (int i = 0; i < used_fields; i++) {
      strcat(tmplt_def, field_names[i]);
      strcat(tmplt_def, ",");
   }
   strcat(tmplt_def, static_fields);

   return tmplt_def;
}

void Config::print()
{
   printf("Used fields: %d\n", used_fields);
   printf("Timeout type: %d\n", timeout_type);
   if (timeout_type == TIMEOUT_ACTIVE_PASSIVE) {
      printf("Timeout Active: %d\n", timeout[TIMEOUT_ACTIVE]);
      printf("Timeout Passive: %d\n", timeout[TIMEOUT_PASSIVE]);
   }
   else {
      printf("Timeout: %d\n", timeout[timeout_type]);
   }

   printf("Fields:\n");
   for (int i = 0; i < used_fields; i++) {
      printf("%d) %s:function(%d) \n",i, field_names[i], functions[i]);
   }
}