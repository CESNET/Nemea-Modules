/**
 * \file flow_meter.h
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havraji6@fit.cvut.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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

#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <string>
#include <vector>

#include "flowcacheplugin.h"

using namespace std;

#ifndef FLOW_CACHE_SIZE
const unsigned int DEFAULT_FLOW_CACHE_SIZE = 131072;
#else
const unsigned int DEFAULT_FLOW_CACHE_SIZE = FLOW_CACHE_SIZE;
#endif
const unsigned int DEFAULT_FLOW_LINE_SIZE = 16;
const double DEFAULT_INACTIVE_TIMEOUT = 30.0;
const double DEFAULT_ACTIVE_TIMEOUT = 300.0;

/**
 * \brief Struct containing module settings.
 */
struct options_t {
   int basic_ifc_num;
   bool eof;
   bool print_stats;
   bool print_pcap_stats;
   uint32_t flow_cache_size;
   uint32_t flow_line_size;
   uint32_t snaplen;
   struct timeval inactive_timeout;
   struct timeval active_timeout;
   struct timeval cache_stats_interval;
   string interface;
   string pcap_file;
};

/**
 * \brief Wrapper for array of plugins.
 */
struct plugins_t {
   vector<FlowCachePlugin *> plugins;

   /**
    * \brief Destructor.
    */
   ~plugins_t() {
      for (unsigned int i = 0; i < plugins.size(); i++) {
         delete plugins[i];
      }
   }
};

#endif
