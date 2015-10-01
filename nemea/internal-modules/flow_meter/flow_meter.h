#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <string>

const unsigned int DEFAULT_FLOW_CACHE_SIZE = 65536;
const unsigned int DEFAULT_FLOW_LINE_SIZE = 32;
const double DEFAULT_INACTIVE_TIMEOUT = 30.0;
const double DEFAULT_ACTIVE_TIMEOUT = 300.0;
const std::string DEFAULT_REPLACEMENT_STRING = \
   "13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0";

#define PLUGIN_HTTP  (0x1 << 0)
#define PLUGIN_DNS   (0x1 << 1)

struct options_t {
   bool statsout;
   bool verbose;
   uint32_t flowcachesize;
   uint32_t flowlinesize;
   uint32_t activeplugins;
   double inactivetimeout;
   double activetimeout;
   double statstime;
   std::string interface;
   std::string infilename;
   std::string outfilename;
   std::string replacementstring;
};

void print_help();

#endif
