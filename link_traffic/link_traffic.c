/**
 * \file link_traffic.c
 * \brief Module used for counting statistics used in Munin.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \author Jaroslav Hlavac <hlavaj20@fit.cvut.cz>
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
#include <stdlib.h>
#include "fields.h"

/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   uint32 PACKETS,
   uint8 DIR_BIT_FIELD
)

trap_module_info_t *module_info = NULL;


/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Link Flows Counter","This module counts statistics according to link and direction.", 1, 0)


/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM)

#define DEF_SOCKET_PATH "/var/run/libtrap/munin_link_traffic"

static volatile int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

typedef struct link_stats {
   volatile uint64_t flows_in;
   volatile uint32_t packets_in;
   volatile uint64_t bytes_in;
   volatile uint64_t flows_out;
   volatile uint32_t packets_out;
   volatile uint64_t bytes_out;
} link_stats_t;

link_stats_t stats[8];

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
      /* creating formated text to be forwarded and parsed by munin_link_flows script */
      size = asprintf(&str,"nix2-in-bytes,nix2-in-flows,nix2-in-packets,nix2-out-bytes,nix2-out-flows,nix2-out-packets,"
         "nix3-in-bytes,nix3-in-flows,nix3-in-packets,nix3-out-bytes,nix3-out-flows,nix3-out-packets,"
         "telia-in-bytes,telia-in-flows,telia-in-packets,telia-out-bytes,telia-out-flows,telia-out-packets,"
         "geant-in-bytes,geant-in-flows,geant-in-packets,geant-out-bytes,geant-out-flows,geant-out-packets,"
         "amsix-in-bytes,amsix-in-flows,amsix-in-packets,amsix-out-bytes,amsix-out-flows,amsix-out-packets,"
         "sanet-in-bytes,sanet-in-flows,sanet-in-packets,sanet-out-bytes,sanet-out-flows,sanet-out-packets,"
         "aconet-in-bytes,aconet-in-flows,aconet-in-packets,aconet-out-bytes,aconet-out-flows,aconet-out-packets,"
         "pioneer-in-bytes,pioneer-in-flows,pioneer-in-packets,pioneer-out-bytes,pioneer-out-flows,pioneer-out-packets\n"
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32","
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32","
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32","
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32","
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32","
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32","
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32","
         "%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32"\n",
         stats[0].bytes_in, stats[0].flows_in, stats[0].packets_in, stats[0].bytes_out, stats[0].flows_out, stats[0].packets_out,
         stats[1].bytes_in, stats[1].flows_in, stats[1].packets_in, stats[1].bytes_out, stats[1].flows_out, stats[1].packets_out,
         stats[2].bytes_in, stats[2].flows_in, stats[2].packets_in, stats[2].bytes_out, stats[2].flows_out, stats[2].packets_out,
         stats[3].bytes_in, stats[3].flows_in, stats[3].packets_in, stats[3].bytes_out, stats[3].flows_out, stats[3].packets_out,
         stats[4].bytes_in, stats[4].flows_in, stats[4].packets_in, stats[4].bytes_out, stats[4].flows_out, stats[4].packets_out,
         stats[5].bytes_in, stats[5].flows_in, stats[5].packets_in, stats[5].bytes_out, stats[5].flows_out, stats[5].packets_out,
         stats[6].bytes_in, stats[6].flows_in, stats[6].packets_in, stats[6].bytes_out, stats[6].flows_out, stats[6].packets_out,
         stats[7].bytes_in, stats[7].flows_in, stats[7].packets_in, stats[7].bytes_out, stats[7].flows_out, stats[7].packets_out);
      if (size > 0) {
         send(client_fd, str, size, 0);
         free(str);
      }

      close(client_fd);
   }
   
   close(fd);
   pthread_exit(0);
}

/* adds data to global array of link_stats_t structures "statistics[]" */   
void count_stats (uint64_t link, uint8_t direction, ur_template_t *in_tmplt, const void *in_rec) {
   if (direction == 0) {
      stats[link].flows_in++;
      stats[link].bytes_in += ur_get(in_tmplt, in_rec, F_BYTES);
      stats[link].packets_in += ur_get(in_tmplt, in_rec, F_PACKETS);
   } else if (direction == 1) {
      stats[link].flows_out++;
      stats[link].bytes_out += ur_get(in_tmplt, in_rec, F_BYTES);
      stats[link].packets_out += ur_get(in_tmplt, in_rec, F_PACKETS);
   }
   return;
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
    * definitions earlier in this file. It also creates a string with short_opt letters for getopt
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
   in_tmplt = ur_create_input_template(0, "BYTES,LINK_BIT_FIELD,PACKETS,DIR_BIT_FIELD", NULL);
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
   
   /* reading data from input and calling count_stats function to save processed data */
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;
      uint64_t link_index;
      uint8_t direction;

      /* Receive data from input interface 0. */
      /* Block if data are not available immediately (unless a timeout is set using trap_ifcctl) */
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

      /* Handling possible errors. */
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      /* Checking size of received data */
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }
      /* get from what collecto data came and in what direction the flow was comming */
      link_index = __builtin_ctzll(ur_get(in_tmplt, in_rec, F_LINK_BIT_FIELD));
      direction = ur_get(in_tmplt, in_rec, F_DIR_BIT_FIELD);
      /* save data according to information got by the code above */
      count_stats(link_index, direction, in_tmplt, in_rec);
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

