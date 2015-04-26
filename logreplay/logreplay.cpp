/**
 * \file logreplay.c
 * \brief Replay CSV file from logger (need -t that generates header).
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Sabik Erik <xsabik02@stud.fit.vutbr.cz>
 * \date 2014
 * \date 2015 
 */
/*
 * Copyright (C) 2014,2015 CESNET
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

#include <inttypes.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <map>

#define DYN_FIELD_MAX_SIZE 1024 // Maximum size of dynamic field, longer fields will be cutted to this size

// Struct with information about module
trap_module_info_t module_info = {
   (char *) "LogReplay", // Module name
   // Module description
   (char *) "This module converts CSV from logger and sends it in UniRec.\n"
   "CSV is expected to have UniRec specifier in the first line (logger -t).\n"
   "\n"
   "Interfaces:\n"
   "   Inputs: 0\n"
   "   Outputs: 1\n"
   "\n"
   "Usage:\n"
   "   ./logreplay -i IFC_SPEC -f FILE\n"
   "\n"
   "Module specific parameters:\n"
   "   -f FILE      Read FILE.\n"
   "   -c N         Quit after N records are received.\n"
   "   -n           Don't send \"EOF message\" at the end.\n"
//   "   -s C         Field separator (default ',').\n"
//   "   -r C         Record separator (default '\\n').\n"
   ,
   0, // Number of input interfaces (-1 means variable)
   1, // Number of output interfaces
};

static int stop = 0;

int verbose;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

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
          case '"': ++quotes;
                    ++in_quotes;
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


void store_value(ur_template_t *t, void *data, int f_id, string &column)
{
   // Check size of dynamic field and if longer than maximum size then cut it
   if (column.length() > DYN_FIELD_MAX_SIZE) {
      column[DYN_FIELD_MAX_SIZE] = 0;
   }
   ur_set_from_string(t, data, f_id, column.c_str());
}

ur_field_id_t urgetidbyname(const char *name)
{
   for (int id = 0; id < UR_FIELDS_NUM; id++) {
      if (strcmp(name, UR_FIELD_NAMES[id]) == 0) {
         return id;
      }
   }
   return UR_INVALID_FIELD;
}

string replace_string(string subject, const string &search, const string &replace) {
   size_t pos = 0;
   while ((pos = subject.find(search, pos)) != std::string::npos) {
      subject.replace(pos, search.length(), replace);
      pos += replace.length();
   }
   return subject;
}

int main(int argc, char **argv)
{
   int ret;
   int send_eof = 1;
   int time_flag = 0;
   char *out_template_str = NULL;
   char *in = NULL, *in_filename = NULL;
   char record_delim = '\n';
   char field_delim = ',';
   char dyn_field_quote = '"'; // dynamic fields are enquoted
   ifstream f_in;
   string line;
   ur_template_t *utmpl = NULL;
   void *data = NULL;
   map<int,string> dynamic_field_map;
   unsigned int num_records = 0; // Number of records received (total of all inputs)
   unsigned int max_num_records = 0; // Exit after this number of records is received
   trap_ctx_t *ctx = NULL;

   // ***** Process parameters *****

   // Let TRAP library parse command-line arguments and extract its parameters
   trap_ifc_spec_t ifc_spec;
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         trap_free_ifc_spec(ifc_spec);
         return 0;
      }
      trap_free_ifc_spec(ifc_spec);
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }

   verbose = trap_get_verbose_level();
   if (verbose >= 0){
      printf("Verbosity level: %i\n", trap_get_verbose_level());
   }

   // Parse remaining parameters and get configuration
   char opt;
   while ((opt = getopt(argc, argv, "f:c:n" /* r:s: */)) != -1) {
      switch (opt) {
         case 'f':
            in_filename = optarg;
            break;
         case 'c':
            max_num_records = atoi(optarg);
            if (max_num_records == 0) {
               fprintf(stderr, "Error: Parameter of -c option must be integer > 0.\n");
               return 1;
            }
            break;
         case 'n':
            send_eof = 0;
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
            goto exit;
      }
   }
   if (in_filename == NULL) {
      fprintf(stderr, "Error: Missing parameter -f with input file.\n");
      goto exit;
   }

   f_in.open(in_filename);

   if (f_in.good()) {
      getline(f_in, line, record_delim);
      if (line.compare(0, 5, "time,") == 0) {
         time_flag = 1;
         line.erase(0,5);
      }
      utmpl = ur_create_template(line.c_str());
      if (utmpl == NULL) {
         goto exit;
      }

      // calculate maximum needed memory for dynamic fields
      int memory_needed = 0;
      ur_field_id_t field_id = UR_INVALID_FIELD;
      while ((field_id = ur_iter_fields(utmpl, field_id)) != UR_INVALID_FIELD) {
         if (ur_is_dynamic(field_id) != 0) {
            memory_needed += DYN_FIELD_MAX_SIZE;
         }
      }

      data = ur_create(utmpl, memory_needed);
      if (data == NULL) {
         goto exit;
      }

      // Initialize TRAP library (create and init all interfaces)
      if (verbose >= 0) {
         printf("Initializing TRAP library ...\n");
      }
      ctx = trap_ctx_init(&module_info, ifc_spec);
      if (ret != TRAP_E_OK) {
         fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
         ret = 2;
         goto exit;
      }

      // Set interface tineout to TRAP_WAIT (and disable buffering (why?))
      trap_ctx_ifcctl(ctx, TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_WAIT);
      //trap_ctx_ifcctl(ctx, TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0);

      stringstream ss(line);
      vector<ur_field_id_t> field_ids;
      string column;

      while (getline(ss, column, field_delim)) {
         field_ids.push_back(urgetidbyname(column.c_str()));
      }


      /* main loop */
      while (f_in.good()) {
         if (num_records++ >= max_num_records) {
            break;
         }

         getline(f_in, line, record_delim);
         if (!f_in.good()) {
            break;
         }
         stringstream sl(line);
         int skipped_time = 0;
         for (vector<ur_field_id_t>::iterator it = field_ids.begin(); it != field_ids.end(); ++it) {
            column = get_next_field(sl);
            // Skip timestamp added by logger
            if (!skipped_time && time_flag) {
               column = get_next_field(sl);
               skipped_time = 1;
            }
            // check if current field is dynamic
            if (ur_is_dynamic(*it) != 0) {
               // dynamic field, just store it in a map for later use
               dynamic_field_map[*it] = column;
            } else {
               // store static field in unirec structure
               store_value(utmpl, data, *it, column);
            }
         }
         // store dynamic fields in correct order to unirec structure
         ur_field_id_t tmpl_f_id;
         ur_iter_t iter = UR_ITER_BEGIN;
         while ((tmpl_f_id = ur_iter_fields_tmplt(utmpl, &iter)) != UR_INVALID_FIELD) {
            if (ur_is_dynamic(tmpl_f_id) != 0) {
               store_value(utmpl, data, tmpl_f_id, dynamic_field_map[tmpl_f_id]);
            }
         }
         trap_ctx_send(ctx, 0, data, ur_rec_size(utmpl, data));
         //trap_ctx_send_flush(ctx, 0);

      }
   }

   // ***** Cleanup *****

exit:
   trap_free_ifc_spec(ifc_spec);
   if (f_in.is_open()) {
      f_in.close();
   }
   if (verbose >= 0) {
      printf("Exitting ...\n");
   }

   if (send_eof) {
      char dummy[1] = {0};
      trap_ctx_send(ctx, 0, dummy, 1);
   }

   trap_ctx_send_flush(ctx, 0);
   trap_ctx_finalize(&ctx);

   if (utmpl != NULL) {
      ur_free_template(utmpl);
      utmpl = NULL;
   }
   if (data != NULL) {
      ur_free(data);
      data = NULL;
   }

   return ret;
}

