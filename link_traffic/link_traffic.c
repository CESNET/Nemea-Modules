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
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define save_tmp "/var/run/libtrap/saved_data.tmp"
#define save_file "/var/run/libtrap/saved_data"

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

#define CONFIG_PATH "/home/nemea/Nemea-Modules/link_traffic/config.txt" 

#define SAVE_FILE "/var/run/libtrap/saved_data"

#define SAVE_TMP "/var/run/libtrap/saved_data.tmp"

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

/* function for initialization temporary file */
int init_f()
{
   /* Create tmp file  */
   FILE *tmp;
   if ( ! (tmp = fopen(save_tmp, "w+")) )
      return 1;
   fclose(tmp);
   return 0;
}

/* function saves input string to defined file */
int saveData (const char *string)
{
   FILE *fp;
   if (! (fp = fopen(save_tmp, "w") )) {
      fprintf(stderr, "Error while opening %s.\n", save_tmp);
      return 1;
   }

   fputs(string, fp);
   fclose(fp);

   if (rename(save_tmp, save_file) == -1 ) {
      fprintf(stderr, "A rename error occurred check if file %s and %s exists.\n", save_tmp, save_file);
   }
   if (!init_f())
      return 0;
   fprintf(stderr,"Error creating tmp file: %s.\n", save_tmp);
   return 1;
} 

/* function which return md_time of file */
time_t mdf_time(char *path) {
   struct stat fst;
   bzero(&fst,sizeof(fst));
   if (stat(path, &fst) != 0) { 
      printf("stat() failed with errno %d\n",errno); exit(-1); 
   }   
   return fst.st_mtime;
}


/*   *** function for parsing config ***
*   function goes through text file line by line and search for specific pattern
*   return names string array 
*   input arg: fileName is path to config file, arrayCnt is counter for array and size 
*   stores size of memory for array */
char **get_link_names(char *filePath, char **linkNames, int *size, int *arrCnt)
{
   FILE *fp;
   char *line = NULL, *name = NULL;
   size_t len = 0;
   ssize_t read;
   printf(">Accesing config file %s.\n", filePath);
   fp = fopen(filePath, "r");

   if (!fp) {
      fprintf(stderr, "Error while opening config file %s\n", filePath);
      return NULL;
   }   

   while ((read = getline(&line, &len, fp)) != -1) {
      if ((name = strstr(line, "name="))) {
         if(*arrCnt >= *size) {
            *size += (*size < 100) ? 10 : *size/2;
            char **tmp = (char**) realloc(linkNames, *size * sizeof(char**));
            if(!tmp) {
               free(linkNames);
               return NULL;
            }
            linkNames = tmp;
         }

         linkNames[*arrCnt] = malloc(sizeof(char) * (strlen(name)-8));
         strncpy(linkNames[*arrCnt], name+6, strlen(name)-8);   
         ++*arrCnt;
      }   
   }   

   fclose(fp);

   if (line)
      free(line);

   printf(">Configuration success.\n");
   return linkNames;
}

/* *** Function for saving data to file used for further analyses.*/
int savaData (char *dataToSave) 
{
   FILE *fp;
   if (!(fp = fopen("SAVE_TMP", "w"))) {
      fprintf(stderr,"Error opening file %s", SAVE_TMP);
      return 1;
   }  
} 

/* creating formated text to be forwarded and parsed by munin_link_flows script */
char *getText(char **linkNames, int link_cnt, int *size) {
   char *data = NULL;
   int i = 0;

   for (i = 0; i < link_cnt; i++) {
      size += asprintf(&data,"%s-in-bytes,%s-in-flows,%s-in-packets,%s-out-bytes,%s-out-flows,%s-out-packets,", linkNames[i],linkNames[i],linkNames[i],linkNames[i],linkNames[i],linkNames[i]);
      }
   for (i = 0; i < link_cnt; i++) {
      size += asprintf(&data,"%" PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32",",stats[i].bytes_in, stats[i].flows_in, stats[i].packets_in, stats[i].bytes_out, stats[i].flows_out, stats[i].packets_out);
   }

   return data;
}

void *accept_clients(void *arg)
{
   int client_fd;
   struct sockaddr_in clt;
   socklen_t soc_size;
   int fd = socket(AF_UNIX, SOCK_STREAM, 0);
   char **linkNames = NULL;
   int link_size = 0, link_cnt = 0;

   /* load names of links form config file */
   linkNames = get_link_names(CONFIG_PATH, linkNames, &link_size, &link_cnt);   
    
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
      int size = 0;
      client_fd = accept(fd, (struct sockaddr *) &clt, &soc_size);
      
      if (client_fd < 0) {
         fprintf(stderr, "Error: Accept failed.\n");
         continue;
      }      
      str = getText(linkNames, link_cnt, &size);
      printf("%s", str);

      if ( size > 0) {
          send(client_fd, str, size, 0);
          size = 0;
      }

      if (str)
         free(str);

      close(client_fd);
   }
   
   if (linkNames)
      free(linkNames);

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
   char **linkNames = NULL;
   int link_size = 0, link_cnt = 0, ret;
   signed char opt;
   ur_template_t *in_tmplt = NULL;
   
   pthread_t accept_thread;
   pthread_attr_t thrAttr; 
   pthread_attr_init(&thrAttr);
   pthread_attr_setdetachstate(&thrAttr, PTHREAD_CREATE_DETACHED); 
   
   /* load names of links form config file */
   linkNames = get_link_names(CONFIG_PATH, linkNames, &link_size, &link_cnt); 

   /* **** TRAP initialization **** */

   /**
    * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
    * definitions earlier in this file. It also creates a string with short_opt letters for getopt
    * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   /**
    * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
2   */
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
   if (!in_tmplt) {
      fprintf(stderr, "Error: Input template could not be created.\n");
      goto cleanup;
   }


   ret = pthread_create(&accept_thread, &thrAttr, accept_clients, NULL);
   if (ret) {
      fprintf(stderr, "Error: Thread creation failed.\n");
      goto cleanup;     
   } 

   /* Create tmp file */
   if (init_f()) {
      fprintf(stderr, "Error initializing temporary file.\n"); 
      return 1;
   }
 
   /* **** Main processing loop **** */
   
   /* reading data from input and calling count_stats function to save processed data */
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;
      uint64_t link_index;
      uint8_t direction;
      time_t curr_t;
      time_t saved_t;  
      char *data;
      double interval = 60.0;

      /* Initialize time stamp and get time from tmp file */
      saved_t = mdf_time(save_tmp);
      time(&curr_t);

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
      
      /* saving loop */
      if (difftime(curr_t, saved_t) > interval) {
         if ( saveData(data) ) { 
            fprintf(stderr, "Error while saving data.\n");
            break;
         }
         else
            printf(">Data saved.\n");
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

   if (linkNames)
      free(linkNames);


   return 0;
}

