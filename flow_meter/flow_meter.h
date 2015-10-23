/**
 * \file flow_meter.h
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <string>
#include <vector>
#include <flowcacheplugin.h>

const unsigned int DEFAULT_FLOW_CACHE_SIZE = 65536;
const unsigned int DEFAULT_FLOW_LINE_SIZE = 32;
const double DEFAULT_INACTIVE_TIMEOUT = 30.0;
const double DEFAULT_ACTIVE_TIMEOUT = 300.0;
const std::string DEFAULT_REPLACEMENT_STRING = \
   "13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0";

/**
 * \brief Struct containing module settings.
 */
struct options_t {
   bool statsout;
   bool verbose;
   uint32_t flowcachesize;
   uint32_t flowlinesize;
   double inactivetimeout;
   double activetimeout;
   double statstime;
   std::string interface;
   std::string infilename;
   std::string outfilename;
   std::string replacementstring;
};

/**
 * \brief Wrapper for array of plugins.
 */
struct plugins_t {
   std::vector<FlowCachePlugin *> plugins;

   /**
    * \brief Destructor.
    */
   ~plugins_t() {
      for (unsigned int i = 0; i < plugins.size(); i++) {
         delete plugins[i];
      }
   }
};

void print_help();

#endif
