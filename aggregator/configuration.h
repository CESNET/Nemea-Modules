//
// Created by slabimic on 26/02/18.
//


#ifndef AGGREGATOR_CONFIGURATION_H
#define AGGREGATOR_CONFIGURATION_H
#define DEFAULT_TIMEOUT 10

#define KEY       0
#define SUM       1
#define AVG       2
#define MIN       3
#define MAX       4
#define FIRST     5
#define LAST      6
#define BIT_OR    7
#define BIT_AND   8

#define TIMEOUT_ACTIVE           0
#define TIMEOUT_PASSIVE          1
#define TIMEOUT_GLOBAL           2
#define TIMEOUT_ACTIVE_PASSIVE   3        // M = Mixed

#define TIMEOUT_TYPES_COUNT      4        // Count of different timeout types

#define STATIC_FIELDS "TIME_FIRST,TIME_LAST,COUNT"

#include "key.h"
#include "output.h"

class Config {
private:
   int functions[MAX_KEY_FIELDS];
   char *field_names[MAX_KEY_FIELDS];
   int used_fields;
   int timeout[TIMEOUT_TYPES_COUNT];
   int timeout_type;
public:
   Config();
   ~Config();
   int get_used_fields();
   const char * get_name(int index);
   bool is_key(int index);
   bool is_func(int index, int func_id);
   agg_func get_function_ptr(int index, ur_field_type_t field_type);
   final_avg get_avg_ptr(int index, ur_field_type_t field_type);
   void add_member(int func, const char *field_name);
   int get_timeout(int type);
   char get_timeout_type();
   void set_timeout(const char *input);
   char * return_template_def();
   // Development methods
   void print();
};

#endif //AGGREGATOR_CONFIGURATION_H