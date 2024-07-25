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
#include <stdbool.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <inttypes.h>
#include <stdint.h>
#include "fields.h"
#include <time.h>

/**
 * @brief Linked list structure for storing flows
 * 
 * This structure is a linked list of bins, that are used to categorize flows based on their age.
 */
typedef struct bins_t {
   uint64_t max_age;
   size_t count_first;
   size_t count_last;
   struct bins_t *next;
} bin;


/**
 * @brief Structure for storing statistics about flow ages
 * 
 * This structure is used to storing general statistics about flow ages encountered during runtime of the program.
*/
typedef struct stats_t {
   uint64_t max;
   uint64_t min;
   uint64_t avg;
} stat;

/**
 * @brief Structure for categorization by FLOW_END_REASON
 * 
 * This structure is used for separating flows into categories based on the reason they ended. 
 * It makes use of the structs defined above to store general statistcs about them and their ages.
 */
typedef struct category_t {
   bin* bins;
   stat* first;
   stat* last;
   uint8_t reason;
   int count;
   struct category_t* next;
} category;

/**
 * @brief Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   time TIME_FIRST,
   time TIME_LAST,
   uint8 FLOW_END_REASON,
)

trap_module_info_t *module_info = NULL;


/**
 * @brief Definition of basic module information
 * 
 * The module information include: module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Flow Age Stats module", \
        "This module finds min, max and avg of ages of flow data from input.\n" \
        "The second function is making percentual histograms of flow ages and outputs them into a file when -t is specified.\n" \
        "The third function is making percentual histograms of flow ages and the reasons why the flow ended into files when -e is specified.\n" , 1, 0)


/**
 * @brief Definition of module parameter
 */
#define MODULE_PARAMS(PARAM)\
   PARAM('t', "table", "Store statistics (histograms) in files", no_argument, "none")\
   PARAM('e', "end reason", "Make separate statistics for different values of FLOW_END_REASON field", no_argument, "none")

//declaration of functions
bin* createNode(uint64_t max, uint64_t count);
void categorizeIntoCats(category* curr, uint64_t first_diff, uint64_t last_diff, uint8_t end_reason);
category* createCategory(category* next, uint8_t reason);
void destroyCategory(category* current);
void printCategories(category* head, int flow_count);
void outputInFiles(category* head, int flow_count);


static int stop = 0;

/**
 * @brief Function to handle SIGTERM and SIGINT signals (used to stop the module)
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

   int file = NULL;
   int endReas = 1;
   /**
    * Handling of arguments
   */
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 't':
         file = 1;
         break;
      case 'e':
         endReas = 5;
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
   if(endReas == 5){
      in_tmplt = ur_define_fields_and_update_template("uint8 FLOW_END_REASON, time TIME_FIRST, time TIME_LAST", in_tmplt);
   }

   

   category* head = createCategory(NULL, 0);
   if(head == NULL){
      destroyCategory(head);
   }
   category* curr = head;
   //initialization of categories
   if (endReas == 5) {
      head->reason = 1;
      for (int i = 2; i <= 5; ++i){
         curr->next = createCategory(NULL, i);
         if(curr->next == NULL){
            goto failure;//jump to cleanup
         }
         curr = curr->next;
      }
      curr->next = createCategory(NULL, 0);
   }

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
      if(endReas == 1){
         categorizeIntoCats(head, first_diff, last_diff, 0);
      }
      else{
         uint8_t reas = ur_get(in_tmplt, in_rec, F_FLOW_END_REASON);
         categorizeIntoCats(head, first_diff, last_diff, reas);
      }
   
      free(received);
   }

   time_t end_time;
   time(&end_time);
   double runtime = difftime(end_time, start_time);//calculating runtimes

   printf("\nRuntime: %0.2lfs\n", runtime);
   printf("Number of flows processed: %zu\n \n", flow_count);
   printCategories(head, flow_count);
   

   //should be outputed to file if specified
   if (file == 1){
      outputInFiles(head, flow_count);
   }
   
   /* **** Cleanup **** */
   failure:

   // clean categories
   while (head != NULL){
      category* next = head->next;
      destroyCategory(head);
      head = next;
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

/**
 * @brief Function for creating the bins
 * 
 * This function creates a Node in the bin list. 
 * 
 * @param max maximal age of the FLOW in this bin
 * @param count counts inside the Node are initialized to this value
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

/**
 * @brief Function to create category_t
 * 
 * This function creates a dynamically allocated category for statistics about flow age stats,
 * and based on the argument -e for FLOW_END_REASON.
 * 
 * @param next next category in list
 * @param reason if -e is specified there are 5 different (default is 1) 
 */
category* createCategory(category* next, uint8_t reason){
   category* newCat = (category*)malloc(sizeof(category));
   if (newCat == NULL) {
      fprintf(stderr, "Error: Memory allocation failed\n");
      return NULL;
   }
   //creating bins
   newCat->bins = createNode(1, 0);
   bin *current = newCat->bins;
   for (uint64_t i = 10; i <= 600; i+=10) {
      current->next = createNode(i, 0);
      if (current->next == NULL){
         return NULL;
      }
      current = current->next;
   }
   current->next = createNode(0, 0);

   //creating stat structs
   newCat->first = (stat*)malloc(sizeof(stat));
   if (newCat->first == NULL) {
      fprintf(stderr, "Error: Memory allocation failed\n");
      return NULL;
   }
   newCat->first->avg = 0;
   newCat->first->min = UINT64_MAX;
   newCat->first->max = 0;

   newCat->last = (stat*)malloc(sizeof(stat));
   if (newCat->last == NULL) {
      fprintf(stderr, "Error: Memory allocation failed\n");
      return NULL;
   }
   newCat->last->avg = 0;
   newCat->last->min = UINT64_MAX;
   newCat->last->max = 0;

   newCat->next = next;
   newCat->reason = reason;
   newCat->count = 0;
   return newCat;
}

/**
 * @brief Function for destroying categories
 * 
 * This function frees the dynamically allocated categories. It also checks if the allocations failed
 * beforehand in createCategory().
 * 
 * @param current category to be destroyed
 */
void destroyCategory(category* current){
   if(current == NULL){
      return;
   }
   //free bins
   bin* curr = current->bins;
   while (curr != NULL){
      bin* next = curr->next;
      free(curr);
      curr = next;
   }
   //free stat structs
   if(current->first == NULL){
      return;
   }
   free(current->first);
   if(current->last == NULL){
      return;
   }
   free(current->last);
   free(current);
}

/**
 * @brief Function for categorization
 * 
 * This function goes through the list of categories and updates the statistics based on FLOW_END_REASON (if -e is specified)
 * or by the default (which is 1). 
 * 
 * @param curr head of the category list
 * @param first_diff difference of TIME_FIRST and current time (in ms)
 * @param last_diff difference of TIME_LAST and current time (in ms)
 * @param end_reason FLOW_END_REASON 
 * 
 */
void categorizeIntoCats(category* curr, uint64_t first_diff, uint64_t last_diff, uint8_t end_reason){
   while (curr != NULL){//loop for categorization
      if(curr->reason != end_reason){
         curr = curr->next;
         continue;
      }
      curr->count++;
      bin* tmp = curr->bins;
      bool first_inc = true;
      bool last_inc = true;
      while (tmp != NULL){
         if (first_inc){
            if(tmp->max_age >= (first_diff/1000)){
               tmp->count_first++;
               first_inc = false;
            }
         }
         if (last_inc){
            if (tmp->max_age >= (last_diff/1000)){
               tmp->count_last++;
               last_inc = false;
            }
         }
         if((!last_inc) && (!first_inc)){
            break;
         }
         if(tmp->next == NULL){
            if (first_inc){
               tmp->count_first++;
            }
            if(last_inc){
               tmp->count_last++;
            }
            break;
         }
         tmp = tmp->next;
      }
      curr->first->avg += first_diff;
      curr->last->avg += last_diff;

      //setting new max or min if needed for first
      if(curr->first->max < first_diff){
         curr->first->max = first_diff;
      }
      else if (curr->first->min > first_diff){
         curr->first->min = first_diff;
      }

      //setting new max or min if needed for last
      if(curr->last->max < last_diff){
         curr->last->max = last_diff;
      }
      else if (curr->last->min > last_diff){
         curr->last->min = last_diff;
      }   
      break;
   }
}

/**
 * @brief Function to print out basic statistics
 * 
 * Function prints out basic statistics of the flow age data. If -e is specified it prints out 5 separate
 * statistics based on which FLOW_END_REASON was encountered.
 * 
 * @param head head of the list of categories
 * @param flow_count count of flows that were received by module
 */
void printCategories(category* head, int flow_count){
   int count = 0;
   while(head != NULL){
      count++;
      switch(head->reason){
         case 1:
            printf("Stats for FLOW_END_REASON = 1 (idle timeout):\nNumber of flows:%d\nPercentage of the flows with this reason: %0.2lf %%\n", head->count, ((double)head->count/flow_count) * 100);
            break;
         case 2:
            printf("Stats for FLOW_END_REASON = 2 (active timeout):\nNumber of flows:%d\nPercentage of the flows with this reason: %0.2lf %%\n", head->count, ((double)head->count/flow_count) * 100);
            break;
         case 3:
            printf("Stats for FLOW_END_REASON = 3 (end of flow detected):\nNumber of flows:%d\nPercentage of the flows with this reason: %0.2lf %%\n", head->count, ((double)head->count/flow_count) * 100);
            break;
         case 4:
            printf("Stats for FLOW_END_REASON = 4 (forced end):\nNumber of flows:%d\nPercentage of the flows with this reason: %0.2lf %%\n", head->count, ((double)head->count/flow_count) * 100);
            break;
         case 5:
            printf("Stats for FLOW_END_REASON = 5 (lack of resources)\nNumber of flows:%d\nPercentage of the flows with this reason: %0.2lf %%\n", head->count, ((double)head->count/flow_count) * 100);
            break;
         default:
            if(count == 1){
               printf("Stats for all flows encountered:\nNumber of flows:%d\n", head->count);
            }
            else{
               printf("Stats for other values of FLOW_END_REASON:\nNumber of flows:%d\nPercentage of the flows with this reason: %0.2lf %%\n", head->count, ((double)head->count/flow_count) * 100);
            }
            break;
      }
      printf("\tMinimal age of time_first: %0.2lf s\n", (double)head->first->min/1000);//from milliseconds to seconds
      printf("\tMaximal age of time_first: %0.2lf s\n", (double)head->first->max/1000);
      printf("\tAverage age of time_first: %0.2lf s\n", (double)(head->first->avg/flow_count)/1000);
      printf("\tMinimal age of time_last: %0.2lf s\n", (double)head->last->min/1000);
      printf("\tMaximal age of time_last: %0.2lf s\n", (double)head->last->max/1000);
      printf("\tAverage age of time_last: %0.2lf s\n\n", (double)(head->last->avg/flow_count)/1000);
      head = head->next;
   }
}

/**
 * @brief Function for outputting into files
 * 
 * This function outputs the tables into files. If the -e is specified tables for each FLOW_END_REASON are created.
 * 
 * @param head head of the category list
 * @param flow_count count of flows encountered
 */
void outputInFiles(category* head, int flow_count){
   char first_file[] = "0_time_first.txt";
   char last_file[] = "0_time_last.txt";
   FILE* out = NULL;

   while (head != NULL){
      first_file[0] = '0' + head->reason;
      out = fopen(first_file, "w");
      if (out == NULL){
         fprintf(stderr, "Error: Could not open file '%s'.\n", first_file);
         return;
      }
      bin* current = head->bins;
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

      last_file[0] = '0' + head->reason;
      out = fopen(last_file, "w");
      if (out == NULL){
         fprintf(stderr, "Error: Could not open file '%s'.\n", last_file);
         return;
      }
      current = head->bins;
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
      head = head->next;
   }
}

