//
// Created by slabimic on 26/02/18.
//

#include "configuration.h"

Config::Config() : used_fields(0), timeout(DEFAULT_TIMEOUT), timeout_type(TIMEOUT_ACTIVE)
{}


Config::~Config()
{
   for (int i = 0; i < used_fields; i++) {
      delete [] field_names[i];
   }
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
            default:
               fprintf(stderr, "Unknown timeout type \'%c\', keeping default.\n", first[0]);
         }
         timeout = atoi(second);
      }
      else {
         timeout = atoi(first);
      }
   }

   if(timeout <= 0) {
      fprintf(stderr, "%d is not > 0, keeping default.\n", timeout);
      timeout = DEFAULT_TIMEOUT;
   }
   delete [] definition;
}

/**
 *
 * @return string which defines ur_template from user input, has to be freed manually
 */
char* Config::return_template_def()
{
   const char *static_fields = "TIME_FIRST,TIME_LAST,COUNT";
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
   printf("Timeout type: %c\nTimeout: %d sec\nUsed fields: %d\n", timeout_type, timeout, used_fields);
   printf("Fields:\n");
   for (int i = 0; i < used_fields; i++) {
      printf("%d) %s:function(%d) \n",i, field_names[i], functions[i]);
   }
}