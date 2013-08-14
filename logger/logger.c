/**
 * \file logger.c
 * \brief Logs incoming UniRec records into file(s). 
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
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
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include "../../unirec/unirec.h"
#include <omp.h>
#include <unistd.h>

// Struct with information about module
trap_module_info_t module_info = {
   "Logger", // Module name
   // Module description
   "This module log all incoming UniRec records into specified files.\n"
   "Number of input intefaces and UniRec formats are specified on command line\n"
   "or using a confirugation file.\n"
   "Interfaces:\n"
   "   Inputs: variable\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};

static int stop = 0;

int verbose;
static int n_inputs; // Number of input interfaces
static ur_template_t **templates; // UniRec templates of input interfaces (array of length n_inputs)
//char **files; // Names of files to write records into (array of length n_inputs)

static FILE *file; // Output file

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);


void capture_thread(int index)
{
   int ret;
   uint32_t ifc_mask = (0x1 << index);
   
   if (verbose >= 1) {
      printf("Thread %i started (using ifc_mask 0x%08x).\n", index, ifc_mask);
   }
   
   // Read data from input and log them to a file
   while (!stop) {
      const void *rec;
      uint16_t rec_size;
      
      if (verbose >= 2) {
         printf("Thread %i: calling trap_get_data()\n", index);
      }
      
      // Receive data from index-th input interface, wait until data are available
      ret = trap_get_data(ifc_mask, &rec, &rec_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
      
      if (verbose >= 2) {
         printf("Thread %i: received %hu bytes of data\n", index, rec_size);
      }
      
      // Check size of received data
      if (rec_size < ur_rec_static_size(templates[index])) {
         if (rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(templates[index]), rec_size);
            break;
         }
      }
      
      #pragma omp critical
      {
         fprintf(file,"%i", index);
         fflush(file);
      }
   }
   
   if (verbose >= 1) {
      printf("Thread %i exitting.\n", index);
   }
}


int main(int argc, char **argv)
{
   int ret;
   char *out_filename = NULL;
   
   // ***** Process parameters *****
   
   // Let TRAP library parse command-line arguments and extract its parameters
   trap_ifc_spec_t ifc_spec;
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }
   
   verbose = trap_get_verbose_level();
   if (verbose >= 0){
      printf("Verbosity level: %i\n", trap_get_verbose_level());
   }
   
   // Parse remaining parameters and get configuration
   char opt;
   while ((opt = getopt(argc, argv, "w:")) != -1) {
      switch (opt) {
         case 'w':
            out_filename = optarg;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 1;
      }
   }
   
   // Create UniRec templates
   n_inputs = argc - 1;
   if (verbose >= 0) {
      printf("Number of inputs: %i\n", n_inputs);
   }
   if (n_inputs < 1) {
      fprintf(stderr, "You must specify at least one UniRec template.\n");
      return 0;
   }
   if (n_inputs > 32) {
      fprintf(stderr, "More than 32 interfaces is not allowed by TRAP library.\n");
      return 4;
   }
   
   if (verbose >= 0) {
      printf("Creating UniRec templates ...\n");
   }
   templates = malloc(n_inputs*sizeof(*templates));
   if (templates == NULL) {
      fprintf(stderr, "Memory allocation error.\n");
      return -1;
   }
   
   for (int i = 0; i < n_inputs; i++) {
      templates[i] = ur_create_template(argv[i+1]);
      if (templates[i] == NULL) {
         fprintf(stderr, "Invalid template: %s\n", argv[i+1]);
         free(templates);
         return 2;
      }
   }
   
   // Set number of input interfaces
   module_info.num_ifc_in = n_inputs;
   
   
   // ***** TRAP initialization *****
   
   if (verbose >= 0) {
      printf("Initializing TRAP library ...\n");
   }
   
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      free(templates);
      trap_free_ifc_spec(ifc_spec);
      return 2;
   }
   
   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);
   
   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   
   
   // ***** Open output file *****
   
   // Open output file if specified
   if (out_filename != NULL) {
      if (verbose >= 0) {
         printf("Creating output file \"%s\" ...\n", out_filename);
      }
      file = fopen(out_filename, "w");
      if (file == NULL) {
         perror("Error: can't open output file:");
         free(templates);
         return 3;
      }
   } else {
      file = stdout;
   }
   
   if (verbose >= 0) {
      printf("Initialization done.\n");
   }
   
   
   // ***** Start a thread for each interface *****
   
   #pragma omp parallel num_threads(n_inputs)
   {
      capture_thread(omp_get_thread_num());
   }
   
   // ***** Cleanup *****

   if (verbose >= 0) {
      printf("Exitting (performing cleanup) ...\n");
   }
   
   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   for (int i = 0; i < n_inputs; i++) {
      ur_free_template(templates[i]);
   }
   
   if (verbose >= 0) {
      printf("Exitting...\n");
   }
   
   return 0;
}

