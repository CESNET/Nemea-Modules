/**
 * \file prot_flows.c
 * \brief Example module used for counting statistics used in Munin.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <pthread.h>
#include <sys/socket.h> 
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include "fields.h"

/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   uint8 PROTOCOL,
   uint64 BYTES,
   uint32 PACKETS
)

trap_module_info_t *module_info = NULL;


/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Protocol Flows Counter","This module counts statistics of protocol usage in flows. (TCP/UDP/ICMP...)", 1, 0)


/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM)

#define DEF_SOCKET_PATH "/var/run/libtrap/munin_proto_traffic"

static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

#define PROTOCOLS(A) \
	A(icmp, 1) \
	A(tcp, 6) \
	A(udp, 17) \
	A(icmp6, 58) \
	A(esp, 50) \
	A(gre, 47)

#define FOREACH_PROTOCOLS(A) PROTOCOLS(A)

#define ENUMS(name, number)	name = number,

enum protocols {
FOREACH_PROTOCOLS(ENUMS)
ENUMS(others, -1)
};

#define STATS(name, number)	volatile uint64_t name;
typedef struct statistics {
FOREACH_PROTOCOLS(STATS)
STATS(others, -1)
} statistics_t;

statistics_t flows, bytes, pckts;

void *accept_clients(void *arg)
{
   int client_fd;
   struct sockaddr_in clt;
   socklen_t soc_size;

   int fd = socket(AF_UNIX, SOCK_STREAM, 0);   
    
   if (fd < 0) {
      fprintf(stderr, "Error: Socket creation failed.\n");
      stop = 1;
      pthread_exit(0);
   }
    
   struct sockaddr_un address;
   bzero(&address, sizeof(address)); 
   address.sun_family = AF_UNIX;
   strcpy(address.sun_path, DEF_SOCKET_PATH);
   unlink(DEF_SOCKET_PATH);
    
   if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
      close(fd);
      fprintf(stderr, "Error: Bind failed.\n");
      stop = 1;
      pthread_exit(0);
   }

   /* changing permissions for socket so munin can read data from it */
   if (chmod(DEF_SOCKET_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0) {
      fprintf(stderr, "Error: Changing permissions failed.\n");
   }

   if (listen(fd, 5) < 0) {
      close(fd);
      fprintf(stderr, "Error: Listen failed.\n");
      stop = 1;
      pthread_exit(0);
   }

   soc_size = sizeof(clt);
   while (!stop) {
      char *str;
      int size;

      client_fd = accept(fd, (struct sockaddr *) &clt, &soc_size);
      if (client_fd < 0) {
         fprintf(stderr, "Error: Accept failed.\n");
         continue;
      }

#define STRING_FLOWS(name, value) #name "-flows,"
#define STRING_BYTES(name, value) #name "-bytes,"
#define STRING_PCKTS(name, value) #name "-packets,"
#define STRING_VALUE(name, value) "%" PRIu64 ","
#define FLOWS_STATS(name, value) flows.name,
#define BYTES_STATS(name, value) bytes.name,
#define PCKTS_STATS(name, value) pckts.name,

      size = asprintf(&str,
            FOREACH_PROTOCOLS(STRING_FLOWS) "others-flows,"
            FOREACH_PROTOCOLS(STRING_BYTES) "others-bytes,"
            FOREACH_PROTOCOLS(STRING_PCKTS) "others-packets\n"
            FOREACH_PROTOCOLS(STRING_VALUE) "%" PRIu64 ","
            FOREACH_PROTOCOLS(STRING_VALUE) "%" PRIu64 ","
            FOREACH_PROTOCOLS(STRING_VALUE) "%" PRIu64 "\n",
            FOREACH_PROTOCOLS(FLOWS_STATS) flows.others,
            FOREACH_PROTOCOLS(BYTES_STATS) bytes.others,
            FOREACH_PROTOCOLS(PCKTS_STATS) pckts.others
            );

      if (size > 0) {
         send(client_fd, str, size, 0);
         free(str);
      }

      close(client_fd);
   }
   
   close(fd);
   pthread_exit(0);
}

int main(int argc, char **argv)
{
   int ret;
   signed char opt;
   ur_template_t *in_tmplt = NULL;
   
   pthread_t accept_thread;
   pthread_attr_t thrAttr; 
   pthread_attr_init(&thrAttr);
   pthread_attr_setdetachstate(&thrAttr, PTHREAD_CREATE_DETACHED);

   /* **** TRAP initialization **** */

   /**
    * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
    * definitions on the lines 69 and 77 of this file. It also creates a string with short_opt letters for getopt
    * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   /**
    * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /**
    * Register signal handler.
    */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   /**
    * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
    * This macro is defined in config.h file generated by configure script
    */
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      default:
         fprintf(stderr, "Error: Invalid arguments.\n");
         goto cleanup;
      }
   }

   /* **** Create UniRec templates **** */
   in_tmplt = ur_create_input_template(0, "PROTOCOL,BYTES,PACKETS", NULL);
   if (!in_tmplt){
      fprintf(stderr, "Error: Input template could not be created.\n");
      goto cleanup;
   }


   ret = pthread_create(&accept_thread, &thrAttr, accept_clients, NULL);
   if (ret) {
      fprintf(stderr, "Error: Thread creation failed.\n");
      goto cleanup;     
   }

   /* **** Main processing loop **** */
   memset(&flows, 0, sizeof(flows));
   memset(&bytes, 0, sizeof(bytes));
   memset(&pckts, 0, sizeof(pckts));

   // Read data from input, process them and write to output
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
      uint8_t prot = ur_get(in_tmplt, in_rec, F_PROTOCOL);
      uint64_t cur_bytes = ur_get(in_tmplt, in_rec, F_BYTES);
      uint64_t cur_pckts = ur_get(in_tmplt, in_rec, F_PACKETS);

#define PROTOCOL_CASE(name, value) case value: \
   flows.name++; \
   bytes.name += cur_bytes; \
   pckts.name += cur_pckts; \
   break;

      switch (prot) {
         FOREACH_PROTOCOLS(PROTOCOL_CASE)
         default:
            flows.others++;
            bytes.others += cur_bytes;
            pckts.others += cur_pckts;
            break;
      }
   }

   /* **** Cleanup **** */
cleanup:
   if (in_tmplt) {
      ur_free_template(in_tmplt);
   }

   pthread_attr_destroy(&thrAttr);
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   ur_finalize();

   return 0;
}

