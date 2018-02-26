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

#define TIMEOUT_ACTIVE  'A'
#define TIMEOUT_PASSIVE 'P'
#define TIMEOUT_GLOBAL  'G'


#include "key.h"

class Config {
private:
   int functions[MAX_KEY_FIELDS];
   char *field_names[MAX_KEY_FIELDS];
   int used_fields;
   int timeout;
   char timeout_type;
public:
   Config();
   ~Config();
   void add_member(int func, const char *field_name);
   void set_timeout(const char *input);
   char * return_template_def();
   // Development methods
   void print();
};

#endif //AGGREGATOR_CONFIGURATION_H