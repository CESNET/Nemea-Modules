/**
 * \file logreplay.c
 * \brief Replay CSV file from logger (need -t that generates header).
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Sabik Erik <xsabik02@stud.fit.vutbr.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 * \date 2017
 * \date 2018
 */
/*
 * Copyright (C) 2014-2018 CESNET
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

#include <unirec/unirec.h>

#include <inttypes.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <libtrap/trap.h>
#include <map>
#include "fields.h"

UR_FIELDS(
)

// Maximum size of dynamic field, longer fields will be cut to this
// size
#define DYN_FIELD_MAX_SIZE 1024

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("logreplay","This module converts CSV from logger and sends it in UniRec. The first row of CSV file has to be data format of fields.",0,1)

#define MODULE_PARAMS(PARAM) \
  PARAM('f', "file", "Specify path to a file to be read.", required_argument, "string") \
  PARAM('c', "cut", "Quit after N records are sent.", required_argument, "uint32") \
  PARAM('d', "disable_timing", "Disable time delays during sending data according to the `time` column.", no_argument, "none") \
  PARAM('n', "no_eof", "Don't send 'EOF message' at the end.", no_argument, "none")

static int stop = 0;

int verbose;

void trap_default_signal_handler(int signal)
{
   static int sig_counter = 0;
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      sig_counter++;
      if (sig_counter > 1) {
         trap_terminate();
      }
   }
}

using namespace std;

string get_next_field(stringstream &line)
{
   string column;
   uint32_t quotes = 0;
   uint32_t in_quotes = 0;
   char prev = 0;
   bool fin = false;
   int ch;

   // skip first quote (only in dynamic fields)
   if (line.peek() == '"') {
      ++quotes;
      line.get(); // remove quote from input
   }

   while (!fin && ((ch = line.get()) != EOF)) {
       switch(ch) {
          case '"':
            if (prev != '\\') { 
               ++quotes;
               ++in_quotes;
            }
            break;
          case ',': // if it was static field (no quotes were present)
                    // or if it was dynamic field (even count of quotes)
           if (quotes == 0 || (prev == '"' && (quotes & 1) == 0)) {
              fin = true;
           }
           break;
       }
       // skip last comma and deduplicate double quotes (store only one)
       if ((ch != '"' || ((in_quotes & 1) == 0)) && !fin) {
          column += ch;
       }
       prev = ch;
   }
   return column;
}


int store_value(ur_template_t *t, void *data, int f_id, string &column)
{
   // Check size of dynamic field and if longer than maximum size then cut it
   if (column.length() > DYN_FIELD_MAX_SIZE) {
      column[DYN_FIELD_MAX_SIZE] = 0;
   }
   return ur_set_from_string(t, data, f_id, column.c_str());
}


string replace_string(string subject, const string &search, const string &replace) {
   size_t pos = 0;
   while ((pos = subject.find(search, pos)) != std::string::npos) {
      subject.replace(pos, search.length(), replace);
      pos += replace.length();
   }
   return subject;
}


time_t convert_timestamp(string &t)
{
   struct tm tm;
   strptime(t.c_str(), "%FT%T", &tm);
   return mktime(&tm);
}

int main(int argc, char **argv)
{
   int ret = 0;
   int tmp;
   int send_eof = 1;
   int time_flag = 0;
   int disable_timing = 0;
   char *in_filename = NULL;
   char record_delim = '\n';
   char field_delim = ',';
   ifstream f_in;
   string line;
   ur_template_t *utmpl = NULL;
   void *data = NULL;
   map<int,string> dynamic_field_map;
   // Number of records sent (total of all inputs)
   unsigned int num_records = 0;
   // Exit after this number of records have been sent
   unsigned int max_num_records = 0;
   char is_limited = 0;
   time_t last_timestamp = 0, cur_timestamp = 0;

   // initialize TRAP interface
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   // set signal handling for termination
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   // ***** Process parameters *****

   verbose = trap_get_verbose_level();
   if (verbose >= 0) {
      printf("Verbosity level: %i\n", trap_get_verbose_level());
   }

   // Parse remaining parameters and get configuration
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'f':
            in_filename = optarg;
            break;
         case 'c':
            max_num_records = atoi(optarg);
            is_limited = 1;
            if (max_num_records == 0) {
               fprintf(stderr, "Error: Parameter of -c option must be integer > 0.\n");
               FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
               return 1;
            }
            break;
         case 'n':
            send_eof = 0;
            break;
         case 'd':
            disable_timing = 1;
            break;
         //case 's':
         //   field_delim = (optarg[0] != '\\' ? optarg[0] : (optarg[1] == 't'?'\t':'\n'));
         //   printf("Field delimiter: 0x%02X\n", field_delim);
         //   break;
         //case 'r':
         //   record_delim = (optarg[0] != '\\' ? optarg[0] : (optarg[1] == 't'?'\t':'\n'));
         //   printf("Record delimiter: 0x%02X\n", record_delim);
         //   break;
         default:
            fprintf(stderr, "Error: Invalid arguments.\n");
            ret = 1;
            goto exit;
      }
   }
   if (in_filename == NULL) {
      fprintf(stderr, "Error: Missing parameter -f with input file.\n");
      ret = 1;
      goto exit;
   }

   f_in.open(in_filename);

   if (f_in.good()) {
      getline(f_in, line, record_delim);
      if (line.compare(0, 5, "time,") == 0) {
         time_flag = 1;
         line.erase(0,5);
      } 
      if ((tmp = ur_define_set_of_fields(line.c_str())) != UR_OK) {
         fprintf(stderr, "Error: Cannot define UniRec fields from header fields (%i).\n", tmp);
         ret = 1;
         goto exit;
      }

      // Set interface timeout to TRAP_WAIT (and disable buffering (why?))
      trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_WAIT);
      //trap_ctx_ifcctl(ctx, TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0);

      char *f_names = ur_ifc_data_fmt_to_field_names(line.c_str());
      if (f_names == NULL) {
         fprintf(stderr, "Error: Cannot convert data format to field names\n");
         ret = 1;
         goto exit;
      }
      line = string(f_names);
      utmpl = ur_create_output_template(0, f_names, NULL);
      free(f_names);
      if (utmpl == NULL) {
         fprintf(stderr, "Error: Cannot create unirec template from header fields.\n");
         ret = 1;
         goto exit;
      }

      // calculate maximum needed memory for dynamic fields
      int memory_needed = 0;
      ur_field_id_t field_id = UR_ITER_BEGIN;
      while ((field_id = ur_iter_fields(utmpl, field_id)) != UR_ITER_END) {
         if (ur_is_dynamic(field_id) != 0) {
            memory_needed += DYN_FIELD_MAX_SIZE;
         }
      }

      data = ur_create_record(utmpl, memory_needed);
      if (data == NULL) {
         fprintf(stderr, "Error: Cannot create template for dynamic fields (not enough memory?).\n");
         ret = 1;
         goto exit;
      }

      stringstream ss(line);
      vector<ur_field_id_t> field_ids;
      string column;

      while (getline(ss, column, field_delim)) {
         ur_field_id_t id = ur_get_id_by_name(column.c_str());

         // Can happen in cases of fields macro (e.g. <COLLECTOR_FLOW>) in the header
         if (id == UR_E_INVALID_NAME) {
            fprintf(stderr, "Error: Invalid unirec field %s\n", column.c_str());
            ret = 3;
            goto exit;
         }
         field_ids.push_back(id);
      }


      /* main loop */
      while (f_in.good() && stop == 0) {
         if ((num_records++ >= max_num_records) && (is_limited == 1)) {
            break;
         }

         getline(f_in, line, record_delim);
         if (!f_in.good()) {
            break;
         }
         stringstream sl(line);
         int skipped_time = 0;
         bool valid = true;
         for (vector<ur_field_id_t>::iterator it = field_ids.begin(); it != field_ids.end(); ++it) {
            column = get_next_field(sl);
            // Skip timestamp added by logger
            if (!skipped_time && time_flag) {
               cur_timestamp = convert_timestamp(column);
               column = get_next_field(sl);
               skipped_time = 1;
            }
            // check if current field is dynamic
            if (ur_is_dynamic(*it) != 0) {
               // dynamic field, just store it in a map for later use
               dynamic_field_map[*it] = column;
            } else {
               // store static field in unirec structure
               if (store_value(utmpl, data, *it, column) != 0) {
                  fprintf(stderr, "Warning: invalid field \"%s\", record %d skipped.\n", column.c_str(), num_records);
                  valid = false;
                  break;
               }
            }
         }
         // store dynamic fields in correct order to unirec structure
         ur_field_id_t field_id = UR_ITER_BEGIN;

         while ((field_id = ur_iter_fields(utmpl, field_id)) != UR_ITER_END) {
            if (ur_is_dynamic(field_id) != 0) {
               if (store_value(utmpl, data, field_id, dynamic_field_map[field_id]) != 0) {
                     fprintf(stderr, "Warning: invalid field \"%s\", record %d skipped.\n", column.c_str(), num_records);
                     valid = false;
                     break;
               };
            }
         }

         /* time delay according to the `time` column */
         if (!disable_timing && time_flag) {
            if ((cur_timestamp > last_timestamp) && (last_timestamp != 0)) {
               sleep(cur_timestamp - last_timestamp);
            }
            last_timestamp = cur_timestamp;
         }

         if (valid) {
            trap_send(0, data, ur_rec_size(utmpl, data));
         }

      }
   } else {
      fprintf(stderr, "Error: Cannot open file.\n");
      ret = 4;
      goto exit;
   }


   // ***** Cleanup *****

exit:
   if (f_in.is_open()) {
      f_in.close();
   }
   if (verbose >= 0) {
      printf("Exiting ...\n");
   }

   if (send_eof) {
      char dummy[1] = {0};
      trap_send(0, dummy, 1);
   }

   trap_send_flush(0);
   trap_finalize();

   if (utmpl != NULL) {
      ur_free_template(utmpl);
      utmpl = NULL;
   }
   if (data != NULL) {
      ur_free_record(data);
      data = NULL;
   }
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return ret;
}

