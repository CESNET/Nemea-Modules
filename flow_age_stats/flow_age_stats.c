/**
 * \file flow_age_stats.c
 * \brief Module computes statistics about flow data age.
 * \author Michal Matejka <xmatejm00@stud.fit.vutbr.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2024 CESNET
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <inttypes.h>
#include <stdint.h>
#include "fields.h"
#include <time.h>

/**
 * Linked list structure for storing histogram of flows ages
 */
typedef struct bins_t {
   uint64_t max_age; //maximal duration of the bin TO DO
   size_t count_first;
   size_t count_last;
   struct bins_t *next;
} bin;


/**
 * Structure for storing statistics about flow ages
*/
typedef struct stats_t {
   uint64_t max;
   uint64_t min;
   uint64_t avg;
} stat;

/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   time TIME_FIRST,
   time TIME_LAST,
)

trap_module_info_t *module_info = NULL;


/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Flow Age Stats module", \
        "This module finds min, max and avg of ages of flow data from input.\n" \
        "It can also make histograms of flow ages and output them into a file when -t is specified.\n", 1, 0)


/**
 * Definition of module parameter
 */
#define MODULE_PARAMS(PARAM)\
   PARAM('t', "table", "store data about the flows in files", no_argument, "none")


/**
 * Function for creating the bins
*/
bin* createNode(uint64_t max, uint64_t count){
   bin* new_node = (bin*)malloc(sizeof(bin));
    if (new_node == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }
    new_node->max_age = max;
    new_node->count_first = count;
    new_node->count_last = count;
    new_node->next = NULL;
    return new_node;
}

static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

int main(int argc, char **argv)
{
   int ret;
   signed char opt;

   /* **** TRAP initialization **** */

   /*
    * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
    * definitions on the lines 71 and 84 of this file. It also creates a string with short_opt letters for getopt
    * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   /*
    * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /*
    * Register signal handler.
    */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   FILE* out = NULL;
   int file = NULL;
   /**
    * Handling of arguments
   */
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 't':
         file = 1;
         break;
      default:
         fprintf(stderr, "Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return -1;
      }
   }

   /* **** Create UniRec templates **** */
   ur_template_t *in_tmplt = ur_create_input_template(0, "TIME_FIRST,TIME_LAST", NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }

   //initialization of the structs for statistics like max, min, avg
   stat first = {0, UINT64_MAX, 0};

   stat last = {0, UINT64_MAX, 0};

   //initialization of age bins
    bin *head = createNode(1, 0);
    bin *current = head;
    for (uint64_t i = 10; i <= 600; i+=10) {
        current->next = createNode(i, 0);
        current = current->next;
    }
   current->next = createNode(0, 0);

   //initialization of time
   time_t rawTime;
   

   /* **** Main processing loop **** */
   size_t flow_count = 0;
   time_t start_time;
   time(&start_time);
   
   // Read data from input, process them and output them into file if specified
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

      // Handle possible errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA
      // TODO: there is probably a faster method to get current time in ur_time_t than by conversion from string
      time(&rawTime);
      struct tm* utc_timeinfo;
      #ifdef _WIN32
      gmtime_s(&rawTime, &utc_timeinfo);
      #else
      utc_timeinfo = gmtime(&rawTime);
      #endif
      char time_received[20];
      strftime(time_received, 20, "%Y-%m-%dT%H:%M:%S", utc_timeinfo);

      ur_time_t* received = malloc(sizeof(ur_time_t));
      if(received == NULL){
         fprintf(stderr, "Error: Malloc for ur_time_t failed.\n");
         break;
      }
      uint8_t check = ur_time_from_string(received, time_received);
      if(check == 1){
         fprintf(stderr, "Error: could not convert string to ur_time_t\n");
         break;
      }

      ur_time_t time_first = ur_get(in_tmplt, in_rec, F_TIME_FIRST);
      ur_time_t time_last = ur_get(in_tmplt, in_rec, F_TIME_LAST);
      //time difference between time at which the flow was received vs the time in the record itself
      uint64_t first_diff = ur_timediff(*received, time_first);
      uint64_t last_diff = ur_timediff(*received, time_last);
      //time will be in milliseconds

      flow_count++;

      //categorization into bins
      bin* curr = head;
      int first_inc = 0;// to make sure it only increments once
      int last_inc = 0;
      //loop for putting the flows into correct bins
      while (curr != NULL){
         if (first_inc == 0){
            if(curr->max_age >= (first_diff/1000)){
               curr->count_first++;
               first_inc++;
            }
         }
         if (last_inc == 0){
            if (curr->max_age >= (last_diff/1000)){
               curr->count_last++;
               last_inc++;
            }
         }
         if(last_inc == 1 && first_inc == 1){
            break;
         }
         if(curr->next == NULL){
            if (first_inc == 0){
               curr->count_first++;
            }
            if(last_inc == 0){
               curr->count_last++;
            }
            break;
         }
         curr = curr->next;
      }
      
      first.avg += first_diff;
      last.avg += last_diff;

      //setting new max or min if needed for first
      if(first.max < first_diff){
         first.max = first_diff;
      }
      else if (first.min > first_diff){
         first.min = first_diff;
      }

      //setting new max or min if needed for last
      if(last.max < last_diff){
         last.max = last_diff;
      }
      else if (last.min > last_diff){
         last.min = last_diff;
      }
      free(received);
   }

   time_t end_time;
   time(&end_time);
   double runtime = difftime(end_time, start_time);//calculating runtimes

   printf("\nRuntime: %0.2lfs\n", runtime);
   printf("Number of flows processed: %zu\n \n", flow_count);
   printf("Minimal age of time_first: %0.2lf s\n", (double)first.min/1000);//from milliseconds to seconds
   printf("Maximal age of time_first: %0.2lf s\n", (double)first.max/1000);
   printf("Average age of time_first: %0.2lf s\n", (double)(first.avg/flow_count)/1000);
   printf("Minimal age of time_last: %0.2lf s\n", (double)last.min/1000);
   printf("Maximal age of time_last: %0.2lf s\n", (double)last.max/1000);
   printf("Average age of time_last: %0.2lf s\n", (double)(last.avg/flow_count)/1000);

   //should be outputed to file if specified
   if(file == 1){
      out = fopen("time_first.txt", "w");
      if (out == NULL){
         fprintf(stderr, "Error: Could not open file 'time_first.txt'.\n");
         goto skip_output;
      }
      current = head;
      while(current != NULL){
         if (current->next == NULL){ // last bin - print label as "+" instead of "0"
            fprintf(out, "%" PRIu64 "+\t%0.2lf%%\t%zu\n", current->max_age, ((double)(current->count_first * 100)/flow_count), current->count_first);
            break;
         }
         fprintf(out, "%" PRIu64 "\t%0.2lf%%\t%zu\n", current->max_age, ((double)(current->count_first * 100)/flow_count), current->count_first);
         if (current->next->next == NULL) {
            // second-to-last bin - store the end of this bin so we can use it in the last one (to print "+" after it)
            current->next->max_age = current->max_age;
         }
         current = current->next;
      }
      fclose(out);

      out = fopen("time_last.txt", "w");
      if (out == NULL){
         fprintf(stderr, "Error: Could not open file 'time_last.txt'.\n");
         goto skip_output;
      }
      current = head;
      while(current != NULL){
         if (current->next == NULL){ // last bin - print label as "+" instead of "0"
            fprintf(out, "%" PRIu64 "+\t%0.2lf%%\t%zu\n", current->max_age, ((double)(current->count_last * 100)/flow_count), current->count_last);
            break;
         }
         fprintf(out, "%" PRIu64 "\t%0.2lf%%\t%zu\n", current->max_age, ((double)(current->count_last * 100)/flow_count), current->count_last);
         if (current->next->next == NULL) {
            // second-to-last bin - store the end of this bin so we can use it in the last one (to print "+" after it)
            current->next->max_age = current->max_age;
         }
         current = current->next;
      }
      fclose(out);
   }

   /* **** Cleanup **** */
   skip_output:
   //cleanup of bins
   current = head;
   while(current != NULL){
      bin* next = current->next;
      free(current);
      current = next;
   }
   
   // Do all necessary cleanup in libtrap before exiting
   TRAP_DEFAULT_FINALIZATION();

   // Release allocated memory for module_info structure
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // Free unirec template
   ur_free_template(in_tmplt);
   ur_finalize();

   return 0;
}
