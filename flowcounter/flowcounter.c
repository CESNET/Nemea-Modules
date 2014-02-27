/**
 * \file flow_counter.h
 * \brief Example module for counting number of incoming flow records. 
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 */

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Flow-counter module", // Module name
   // Module description
   "Example module for counting number of incoming flow records.\n"
   "Parameters:\n"
   "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
   "   -p N        Show progess - print a dot every N flows.\n"
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;
static int stats = 0;
static int progress = 0;

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   } else if (signal == SIGUSR1) {
      stats = 1;
   }
}

int main(int argc, char **argv)
{
   int ret;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   
   // ***** TRAP initialization *****
   
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGUSR1, signal_handler);
   
   // ***** Create UniRec template *****
   
   char *unirec_specifier = "<COLLECTOR_FLOW>";
   char opt;
   while ((opt = getopt(argc, argv, "u:p:")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
            break;
         case 'p':
            progress = atoi(optarg);
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 3;
      }
   }
   
   ur_template_t *tmplt = ur_create_template(unirec_specifier);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      return 4;
   }
   
   
   // ***** Main processing loop *****
   
   while (!stop) {
      // Receive data from input interface (block until data are available)
      const void *data;
      uint16_t data_size;
      ret = trap_recv(0, &data, &data_size);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      
      // Check size of received data
      if (data_size < ur_rec_static_size(tmplt)) {
         if (data_size <= 1) {
            break; // End of data (used for testing purposes)
         }
         else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(tmplt), data_size);
            break;
         }
      }
      
      if (progress > 0 && cnt_flows % progress == 0) {
         printf(".");
         fflush(stdout);
      }
      
      // Update counters
      cnt_flows += 1;
      cnt_packets += ur_get(tmplt, data, UR_PACKETS);
      cnt_bytes += ur_get(tmplt, data, UR_BYTES);
      if (stats == 1) {
         printf("Time: %lu\n", (long unsigned int) time(NULL));
         printf("Flows:   %20lu\n", cnt_flows);
         printf("Packets: %20lu\n", cnt_packets);
         printf("Bytes:   %20lu\n", cnt_bytes);
         signal(SIGUSR1, signal_handler);
         stats = 0;
      }
   }
   
   // ***** Print results *****

   if (progress > 0) {
      printf("\n");
   }
   printf("Flows:   %20lu\n", cnt_flows);
   printf("Packets: %20lu\n", cnt_packets);
   printf("Bytes:   %20lu\n", cnt_bytes);
   
   // ***** Cleanup *****
   
   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   
   ur_free_template(tmplt);
   
   return 0;
}

