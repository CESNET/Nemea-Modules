/**
 * \file flow_counter.h
 * \brief Example module for counting number of incoming flow records. 
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 */

#include <signal.h>
#include <stdio.h>
#include <stdint.h>

#include <libtrap/trap.h>
#include "../../unirec/unirec.h"

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Flow-counter module", // Module name
   // Module description
   "Example module for counting number of incoming flow records.\n"
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   }
}

int main(int argc, char **argv)
{
   int ret;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   
   // ***** Create UniRec template *****
   ur_template_t *tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS");
   
   // ***** TRAP initialization *****
   trap_ifc_spec_t ifc_spec;
   
   // Let TRAP library parse command-line arguments and extract its parameters
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      return 2;
   }
   trap_free_ifc_spec(ifc_spec);
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   
   // ***** Main processing loop *****
   
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_TERMINATED) {
            // Module was terminated (e.g. by Ctrl-C)
            break;
         } else {
            // Some error ocurred
            fprintf(stderr, "Error: trap_get_data() returned %i (%s)\n", ret, trap_last_error_msg);
            break;
         }
      }
      
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
      
      // Update counters
      cnt_flows += 1;
      cnt_packets += ur_get(tmplt, data, UR_PACKETS);
      cnt_bytes += ur_get(tmplt, data, UR_BYTES);
   }
   
   // ***** Print results *****

   printf("Flows:   %20lu\n", cnt_flows);
   printf("Packets: %20lu\n", cnt_packets);
   printf("Bytes:   %20lu\n", cnt_bytes);
   
   // ***** Cleanup *****
   
   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
   trap_finalize();
   
   ur_free_template(tmplt);
   
   return 0;
}

