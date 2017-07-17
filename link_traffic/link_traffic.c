/**
 * \file link_traffic.c
 * \brief Module used for counting statistics used in Munin.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \author Jaroslav Hlavac <hlavaj20@fit.cvut.cz>
 * \author Ladislav Macoun <macoulad@fit.cvut.cz>
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
#include <stdlib.h>
#include "fields.h"
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>

#define SAVE_FILE "/var/run/libtrap/saved_data"
#define SAVE_TMP SAVE_FILE ".tmp"

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
#define CONFIG_PATH SYSCONFDIR"/link_traffic/link_traff_conf.cfg"
#define CONFIG_VALUES 4 /* Definition of how many values link's config has. */
/* Definition of config attributes */
#define LINK_NUM 		      1
#define LINK_NAME       	2
#define LINK_UR_FIELD		3
#define LINK_COL		      4
#define CONFIG_VALUES 4 //Definition of how many values link's config has. 

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

/* global dynamic array od link_stats_t structure for statistics */
link_stats_t *stats = NULL;

typedef struct link_conf {
   int         m_num;        /*!int number of link*/
   char        *m_name;      /*!string name of link*/
   char        *m_ur_field;  /*!string link bit field of link*/ 
   int         m_color;      /*!int represents hex value of link's color*/
} link_conf_t;

/* structure used for loading configuration from file and passing it
 * to the thread */
typedef struct link_loaded {
   link_conf_t    **conf;    /*! struct of loaded links configuration */
   size_t         num;       /*! size_t number of loaded links */
} link_load_t;

char *file_header = NULL;

/* 
 * @brief allocates memory for link_stats_t structure array 
 * 
 * size of array is based on number of links loaded from 
 * configuration file, @fn load_links has to be run before executing 
 * this function 
 * @return allocated array of link_stats_t structure statistics 
 * */
link_stats_t *stats_allocator(size_t link_cnt) 
{
   if (stats) {
      free(stats);
   }
   link_stats_t *r_stats = (link_stats_t*) 
                           calloc(sizeof(link_stats_t), link_cnt);
   return !r_stats ? NULL : r_stats;
}

/* initialize temporary file */
int init_f()
{
   /* create tmp file  */
   FILE *tmp;
   if (!(tmp = fopen(SAVE_TMP, "w+"))) {
      return 1;
   }
   fclose(tmp);
   return 0;
}

/* saves input string to defined save file */
int save_data(const char *string)
{
   FILE *fp;
   if (!(fp = fopen(SAVE_TMP, "w") )) {
      fprintf(stderr, "Error while opening %s.\n", SAVE_TMP);
      return 1;
   }
   
   fputs(string, fp);
   fclose(fp);

   if (rename(SAVE_TMP, SAVE_FILE) == -1 ) {
      fprintf(stderr, "A rename error occurred check if file %s and %s exists.\n", SAVE_TMP, SAVE_FILE);
   }
   if (!init_f())
      return 0;
   fprintf(stderr,"Error creating tmp file: %s.\n", SAVE_TMP);
   return 1;
}

/* get md_time of file  */
time_t mdf_time(char *path) {
   struct stat fst;
   bzero(&fst,sizeof(fst));
   if (stat(path, &fst) != 0) {
      printf("stat() failed with errno %d\n",errno); exit(-1);
   }
   return fst.st_mtime;
}

/*! @brief function that clears link_conf array 
 * @return positive value on success otherwise negative 
 * */
void clear_links(link_conf_t **links) 
{  
   size_t i = 0;
   /* don't clear when it's empty */
   if (!links) {
      return;
   }
   
   while (links[i]) {
      /* delete link's name */
      if (links[i]->m_name) {
         free(links[i]->m_name);
      }
   
      if (links[i]->m_ur_field) {
         free(links[i]->m_ur_field);
      }
      free(links[i]);
      i++;
   }
   free(links);
}

/*   *** Parsing link names from config file ***
*   Function goes through text file line by line and search for specific pattern
*   input arg: fileName is path to config file, arrayCnt is counter for array and size
*   stores size of memory for array 
*   */
link_conf_t **load_links(const char *filePath,
                        link_conf_t **links, 
                        size_t *arrCnt)
{
   FILE *fp;
   char *line = NULL, *tok = NULL, *save_pt1 = NULL, *str1 = NULL;
   size_t attribute = 0, len = 0, size = 10;
   int num = 0;
   ssize_t read;
   *arrCnt = 0;

   printf(">Accessing config file %s.\n", filePath);
   links = (link_conf_t**) malloc(size * sizeof(link_conf_t**));
   
   if (links == NULL) {
      goto failure;
   }

   fp = fopen(filePath, "r");

   if (!fp) {
      fprintf(stderr, "Error while opening config file %s\n", filePath);
      goto failure;
   }

   /* start parsig csv config here. */ 
   while ((read = getline(&line, &len, fp)) != -1) {
      if (*arrCnt >= size) { //check if there is enough space allocated
         size *= 2;        
         link_conf_t **tmp = (link_conf_t **)
                             realloc(links, size * sizeof(link_conf_t **));
         if (!tmp) {
            goto failure;
         }
         links = tmp;
      }
      
      link_conf_t *new_link = (link_conf_t*) malloc(sizeof(link_conf_t));

      for (attribute = LINK_NUM, str1 = line; ;attribute++, str1 = NULL) {
         tok = strtok_r(str1, ",", &save_pt1);
         if (tok == NULL) {
             break;
         }

         switch (attribute) {
         case LINK_NUM: //parsing link number
            num = 0;
            if (sscanf(tok, "%d", &num) == EOF) {
               fprintf(stderr, ">config parser error: parsing number failed!");
               goto failure;
            }
            new_link->m_num = num;
            break;

         case LINK_NAME: //parsing link name
            new_link->m_name  = (char*) calloc(sizeof(char), strlen(tok) + 1);
            if (!new_link->m_name) {
               goto failure;
            }
            memcpy(new_link->m_name, tok, strlen(tok));
            break;
            
         case LINK_UR_FIELD: //parsing UR_FIELD 
            new_link->m_ur_field  = (char*) calloc(sizeof(char), strlen(tok) + 1);
            if (!new_link->m_ur_field) {
               goto failure;
            }
            memcpy(new_link->m_ur_field, tok, strlen(tok));
            break;

         case LINK_COL: //parsing line color
            num = 0;
            if (sscanf(tok, "%d", &num) == EOF) {
               fprintf(stderr, ">config parser error: parsing number failed!");
               goto failure;
            }
            new_link->m_color = num;
            break;
         }
         links[*arrCnt] = new_link;
      }
      ++(*arrCnt);
      free(line);
      line = NULL;
      len = 0;
   }
   fclose(fp);
   free(line);
   printf(">Configuration success.\n");
   return links;

failure:
   clear_links(links);
   free(line);
   return NULL;
}

/**
 * Pointer to null-terminated string that will be sent/stored.
 */
static char *databuffer = NULL;

/**
 * Size of allocated memory of databuffer.
 */
size_t databuffer_size = 0;

/**
 * size of the first line including '\n'
 */
size_t header_len = 0;

/**
 * Create formated text to be forwarded and parsed by munin_link_flows script
 * \return Positive number with size of string to be sent/stored or 0 on error.
 */
int prepare_data(link_conf_t **links, const size_t link_cnt)
{
   size_t i = 0, size;

   if (databuffer == NULL) {
      databuffer = calloc(4096, sizeof(char));
      if (databuffer == NULL) {
         return 0;
      }
      databuffer_size = 4096;
      header_len = 0;

      for (i = 0; i < link_cnt; i++) {
         header_len += snprintf(databuffer + header_len, databuffer_size - header_len, "%s-in-bytes,%s-in-flows,%s-in-packets,%s-out-bytes,%s-out-flows,%s-out-packets,", links[i]->m_name,links[i]->m_name,links[i]->m_name,links[i]->m_name,links[i]->m_name,links[i]->m_name);
      }
      databuffer[header_len - 1] = '\n';
   }

   size = header_len;
   for (i = 0; i < link_cnt; i++) {
      size += snprintf(databuffer + size, databuffer_size - size, "%"
                       PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32",",
                       stats[i].bytes_in, stats[i].flows_in, stats[i].packets_in,
                       stats[i].bytes_out, stats[i].flows_out, stats[i].packets_out);
   }
   databuffer[size - 1] = '\n';
   databuffer[size] = '\0';

   return size;
}

void send_to_sock(const int client_fd, char *str)
{
   size_t size = strlen(str), sent = 0;
   const char *tmp = str;

   if (size > 0) {
      tmp = str;
      while (size > 0) {
         sent = send(client_fd, tmp, size, MSG_NOSIGNAL);
         if (sent > 0) {
            size -= sent;
            tmp += sent;
         } else {
            break;
         }
      }
   }
   close(client_fd);
}

void *accept_clients(void *arg)
{
   int client_fd;
   struct sockaddr_in clt;
   socklen_t soc_size;
   int fd = socket(AF_UNIX, SOCK_STREAM, 0);
   char *data = NULL;
   size_t interval = 60;
   time_t curr_t;
   time_t saved_t;

   /* check if configuration is not corrupted */
   link_load_t *loaded = (link_load_t *) arg;
   if (!loaded) {
      fprintf(stderr, "Error: Thread failed to recieve configuration.");
      stop = 1;
      goto cleanup;
   } 
   
   /* create tmp file */
   if (init_f()) {
      fprintf(stderr, "Error: Initializing temporary file.\n");
      stop = 1;
      goto cleanup;
   }
  
   if (fd < 0) {
      fprintf(stderr, "Error: Socket creation failed.\n");
      stop = 1;
      goto cleanup;
   }

   struct sockaddr_un address;
   bzero(&address, sizeof(address));
   address.sun_family = AF_UNIX;
   strcpy(address.sun_path, DEF_SOCKET_PATH);
   unlink(DEF_SOCKET_PATH);

   if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
      close(fd);
      fprintf(stderr, "Error: Bind failed.\n");
      goto cleanup;
      stop = 1;
   }

   /* changing permissions for socket so munin can read data from it */
   if (chmod(DEF_SOCKET_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0) {
      fprintf(stderr, "Error: Changing permissions failed.\n");
   }

   if (listen(fd, 5) < 0) {
      close(fd);
      fprintf(stderr, "Error: Listen failed.\n");
      stop = 1;
      goto cleanup;
   }

   soc_size = sizeof(clt);

   fd_set rfds;
   struct timeval tv;
   int retval;

   while (!stop) {
      data = NULL;
      FD_ZERO(&rfds);
      FD_SET(fd, &rfds);

      /* saving loop **************************************/

      /* wait up to five seconds. */
      tv.tv_sec = 5;
      tv.tv_usec = 0;

      /* initialize time stamp and get time from tmp file */
      saved_t = mdf_time(SAVE_TMP);
      time(&curr_t);

      /* check for timeout */
      retval  = select(fd + 1, &rfds, NULL, NULL, &tv);

      if (retval == -1 ) {
         fprintf(stderr,"Error : select().\n");
         break;
      } else if (!retval) {
         if (prepare_data(loaded->conf, loaded->num) > 0) {
            if (save_data(databuffer) ) {
               fprintf(stderr, "Error while saving data.\n");
               break;
            }
         }

      } else if (retval) {
         client_fd = accept(fd, (struct sockaddr *) &clt, &soc_size);
         if (client_fd < 0) {
            fprintf(stderr, "Error: Accept failed.\n");
            continue;
         }

         if (prepare_data(loaded->conf, loaded->num) > 0) {
            send_to_sock(client_fd, databuffer);
            if (difftime(curr_t, saved_t) >= interval) {
               if (save_data(databuffer) ) {
                  fprintf(stderr, "Error while saving data.\n");
                  break;
               } else {
                  printf(">Data saved.\n");
                  saved_t = mdf_time(SAVE_TMP);

               }
            }
         }
      }

      if (data) {
         free(data);
      }
   }
/* clean up */
cleanup:
   if (stats) {
      free(stats);
   }
   clear_links(loaded->conf);
   close(fd);
   pthread_exit(0);
}

/* adds data to global array of link_stats_t structures "statistics[]" */
void count_stats (uint64_t link,
                  uint8_t direction,
                  ur_template_t *in_tmplt,
                  const void *in_rec
                 ) 
{
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
   signed char opt;
   ur_template_t *in_tmplt = NULL;
   link_conf_t **links = NULL;
   size_t link_cnt;
   link_load_t *loaded = NULL;

   pthread_t accept_thread;
   pthread_attr_t thrAttr;
   pthread_attr_init(&thrAttr);
   pthread_attr_setdetachstate(&thrAttr, PTHREAD_CREATE_DETACHED);

   /* return value for control of opening sockets and saving loop */
   int ret = 0;

   /* load links configuration file */
   if (!(links = load_links(CONFIG_PATH, links, &link_cnt))) {
      fprintf(stderr, "Error loading configuration.\n");
      clear_links(links);
      return 1;
   }

   loaded = (link_load_t *) malloc(sizeof(link_load_t));
   if (!loaded) {
      fprintf(stderr, "Error while allocating memory for loaded configuration.\n")
      clear_links(links);
      free(loaded);
      return 1;
   }
   loaded->conf = links;
   loaded->num = link_cnt; 

   /* allocate memory for stats, based on loaded number of links */
   if (!(stats = stats_allocator(link_cnt))) {
      fprintf(stderr, "Error while allocating memory for stats.\n");
      clear_links(links);
      free(loaded);
      return 1;
   }

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

   ret = pthread_create(&accept_thread, 
                        &thrAttr,
                        accept_clients,
                        (void*) loaded);
   
   if (ret) {
      fprintf(stderr, "Error: Thread creation failed.\n");
      goto cleanup;
   }

   /* **** Main processing loop **** */
   /* 
    * reading data from input and calling count_stats function to save 
    * processed data 
    * */
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;
      uint64_t link_index;
      uint8_t direction;

      /* Receive data from input interface 0. */
      /* Block if data are not available immediately (unless a timeout
       * is set using trap_ifcctl) */
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
      /* get from what collecto data came and in what direction the flow 
       * was comming */
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
   if (stats) {
      free(stats);
   }
   clear_links(links);
   if (loaded) {
      free(loaded);
   }
   pthread_attr_destroy(&thrAttr);
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   ur_finalize();
   return 0;
}

