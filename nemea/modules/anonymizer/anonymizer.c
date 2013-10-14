/**
 * \file anonymizer.h
 * \brief Module for anonymizing incoming flow records. 
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2013
 */

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <libtrap/trap.h>
#include "../../unirec/unirec.h"
#include "../../common/common.h"
#include "panonymizer.h"



#define IP_V4_OFFSET 8          // Unirec format offset for IPv4
#define IP_V6_SIZE 16           // 128b or 16B is size of IP address version 6

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Anonymizer", // Module name
   // Module description
   "Module for anonymizing incoming flow records.\n"
   "Parameters:\n"
   "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
   "Interfaces:\n"
   "   Inputs: 1\n"
   "   Outputs: 1\n",
   1, // Number of input interfaces
   1, // Number of output interfaces
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



/**
 *
 *
 *
 */
void init_key_from_file(uint8_t *init_key)
{
   char *secret_key = "Tajny kluc......................";

   ParseCryptoPAnKey(secret_key, init_key);
   PAnonymizer_Init(init_key);
}





/**
 *
 *
 *
*/
void ip_anonymize(ur_template_t *tmplt, const void *data)
{
   uint32_t  ip_v4_anon;
   uint32_t *ip_v4_ptr;
   uint64_t  ip_v6_anon[2];
   uint64_t *ip_v6_ptr;

   if (ip_is4(ur_get_ptr(tmplt, data, UR_SRC_IP))) {
      // Anonymize SRC IP version 4
      ip_v4_ptr = (uint32_t *)(((uint8_t *)ur_get_ptr(tmplt, data, UR_SRC_IP)) + IP_V4_OFFSET);
      ip_v4_anon = anonymize(ntohl(*ip_v4_ptr));
      *ip_v4_ptr = htonl(ip_v4_anon);

      // Anonymize DST IP version 4
      ip_v4_ptr = (uint32_t *)(((uint8_t *)ur_get_ptr(tmplt, data, UR_DST_IP)) + IP_V4_OFFSET);
      ip_v4_anon = anonymize(ntohl(*ip_v4_ptr));
      *ip_v4_ptr = htonl(ip_v4_anon);
   } else {
      // Anonymize SRC IP version 6
      ip_v6_ptr = (uint64_t *) ur_get_ptr(tmplt, data, UR_SRC_IP);
      anonymize_v6(ip_v6_ptr, ip_v6_anon);
      memcpy(ip_v6_ptr, ip_v6_anon, IP_V6_SIZE);

      // Anonymize DST IP version 6
      ip_v6_ptr = (uint64_t *) ur_get_ptr(tmplt, data, UR_DST_IP);
      anonymize_v6(ip_v6_ptr, ip_v6_anon);
      memcpy(ip_v6_ptr, ip_v6_anon, IP_V6_SIZE);
   }


}




int main(int argc, char **argv)
{
   int ret;
   char ip1_buff[100] = {0};  
   char ip2_buff[100] = {0};


   uint8_t init_key[16] = {0};
   init_key_from_file(init_key);


   // ***** TRAP initialization *****   
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGUSR1, signal_handler);
   


   // ***** Create UniRec template *****   
   char *unirec_specifier = "<BASIC_FLOW>";
   char opt;
   while ((opt = getopt(argc, argv, "u:")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
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
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
      
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
      
     
      /* DEBUG PRINT FOR TESTING
      ip_to_str(ur_get_ptr(tmplt, data, UR_SRC_IP), ip1_buff);
      ip_to_str(ur_get_ptr(tmplt, data, UR_DST_IP), ip2_buff);
      printf("ORIG: %15s   ->   %15s\n", ip1_buff, ip2_buff);     
      
      ip_anonymize(tmplt, data);
      ip_to_str(ur_get_ptr(tmplt, data, UR_SRC_IP), ip1_buff);
      ip_to_str(ur_get_ptr(tmplt, data, UR_DST_IP), ip2_buff);
      printf("ANON: %15s   ->   %15s\n\n", ip1_buff, ip2_buff);*/


      ip_anonymize(tmplt, data);

      // Send anonymized data
      trap_send_data(0, data, ur_rec_size(tmplt, data), TRAP_WAIT); 


   }
   

     char dummy[1] = {0};
     trap_send_data(0, dummy, 1, TRAP_WAIT); 
   
   // ***** Do all necessary cleanup before exiting *****
   TRAP_DEFAULT_FINALIZATION();
   ur_free_template(tmplt);
   
   return 0;
}

