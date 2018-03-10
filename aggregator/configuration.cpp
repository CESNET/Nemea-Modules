//
// Created by slabimic on 26/02/18.
//

#include "configuration.h"

Config::Config() : used_fields(0), timeout_type(TIMEOUT_ACTIVE)
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

agg_func Config::get_function_ptr(int index, ur_field_type_t field_type)
{
   agg_func out = &nope;
   if ((index < 0) || (index > used_fields - 1)) {
      return out;
   }

   switch (functions[index]) {
      case SUM:
         switch (field_type) {
            case UR_TYPE_INT8:
               out = &sum_int8;
               break;
            case UR_TYPE_INT16:
               out = &sum_int16;
               break;
            case UR_TYPE_INT32:
               out = &sum_int32;
               break;
            case UR_TYPE_INT64:
               out = &sum_int64;
               break;
            case UR_TYPE_UINT8:
               out = &sum_uint8;
               break;
            case UR_TYPE_UINT16:
               out = &sum_uint16;
               break;
            case UR_TYPE_UINT32:
               out = &sum_uint32;
               break;
            case UR_TYPE_UINT64:
               out = &sum_uint64;
               break;
            case UR_TYPE_FLOAT:
               out = &sum_float;
               break;
            case UR_TYPE_DOUBLE:
               out = &sum_double;
               break;
            default:
               fprintf(stderr, "Only int, uint, float and double can use sum function, nope assigned instead.\n");
               out = &nope;
         }
         break;
      case AVG:
         switch (field_type) {
            case UR_TYPE_INT8:
               out = &avg_int8;
               break;
            case UR_TYPE_INT16:
               out = &avg_int16;
               break;
            case UR_TYPE_INT32:
               out = &avg_int32;
               break;
            case UR_TYPE_INT64:
               out = &avg_int64;
               break;
            case UR_TYPE_UINT8:
               out = &avg_uint8;
               break;
            case UR_TYPE_UINT16:
               out = &avg_uint16;
               break;
            case UR_TYPE_UINT32:
               out = &avg_uint32;
               break;
            case UR_TYPE_UINT64:
               out = &avg_uint64;
               break;
            case UR_TYPE_FLOAT:
               out = &avg_float;
               break;
            case UR_TYPE_DOUBLE:
               out = &avg_double;
               break;
            default:
               fprintf(stderr, "Only int, uint, float and double can use avg function, nope assigned instead.\n");
               out = &nope;
         }
         break;
      case MIN:
         // Function not implemented yet
         out = &nope;
         break;
      case MAX:
         // Function not implemented yet
         out = &nope;
         break;
      case FIRST:
         // Keep nope function because first value is set by copy from input record
         out = &nope;
         break;
      case LAST:
         // Function not implemented yet
         out = &nope;
         break;
      case BIT_OR:
         // Function not implemented yet
         out = &nope;
         break;
      case BIT_AND:
         // Function not implemented yet
         out = &nope;
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

char Config::get_timeout_type()
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
            printf("second: %s\n", second);
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
                  fprintf(stderr, "Wrong timeout type definition \"-m:Active,Passive\"\n"
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