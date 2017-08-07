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
#include <ctype.h>
/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   uint32 PACKETS,
   uint8 DIR_BIT_FIELD,
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
#define CONFIG_VALUES      4 //Definition of how many values link's config has.

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
   uint64_t       m_val;            /*!int number of link*/
   char           *m_name;          /*!string name of link*/
   char           *m_ur_field;      /*!string link bit field of link*/
   uint32_t       m_color;          /*!int represents hex value of link color*/
   uint16_t       m_id;             /*!uint16_t a unique link identificator */
} link_conf_t;

/* structure used for loading configuration from file and passing it
 * to the thread */
typedef struct link_loaded {
   link_conf_t    *conf;    /*! struct of loaded links configuration */
   size_t         num;       /*! size_t number of loaded links */
} link_load_t;

/*! @brief function that clears link_conf array
 * @return positive value on success otherwise negative
 * */
void clear_conf_struct(link_load_t *links)
{
   int i;
   /* don't clear when it's empty */
   if (!links) {
      return;
   }

   if (links->conf) {
      for (i = 0; i < links->num; i++) {
         if (links->conf[i].m_name) {
            free(links->conf[i].m_name);
         }

         if (links->conf[i].m_ur_field) {
            free(links->conf[i].m_ur_field);
         }

      }

      free(links->conf);
   }

   free(links);
}

/*! @brief a compare function for quick sort using link_conf_t structure */
int confcmp(const void *cfg1, const void *cfg2)
{
   return ((link_conf_t *) cfg2)->m_val - ((link_conf_t *) cfg1)->m_val;
}

/*   *** Parsing link names from config file ***
*   Function goes through text file line by line and search for specific pattern
*   input arg: fileName is path to config file, arrayCnt is counter for array and size
*   stores size of memory for array
*   */
int load_links(const char *filePath, link_load_t *links)
{
   FILE *fp = NULL;
   char *line = NULL, *tok = NULL, *save_pt1 = NULL, *str1 = NULL, *it;
   size_t attribute = 0, len = 0, size = 10;
   int num = 0;
   ssize_t read;

   if (!links) {
      fprintf(stderr, "Error: load_links received NULL pointer\n");
      return 1;
   }

   links->conf = (link_conf_t *) calloc(size, sizeof(link_conf_t));
   if (!links->conf) {
      fprintf(stderr, "Error: Cannot allocate memory for links.\n");
      goto failure;
   }

   links->num = 0;
   printf("Accessing config file %s.\n", filePath);
   fp = fopen(filePath, "r");
   if (!fp) {
      fprintf(stderr, "Error while opening config file %s\n", filePath);
      goto failure;
   }

   /* start parsig csv config here. */
   while ((read = getline(&line, &len, fp)) != -1) {
      if (links->num >= size) { //check if there is enough space allocated
         size *= 2;
         link_conf_t *tmp = (link_conf_t *)
                             realloc(links->conf, size * sizeof(link_conf_t));
         if (!tmp) {
            fprintf(stderr, "Error while reallocating memory for links.\n");
            goto failure;
         }

         links->conf = tmp;
      }

      it = line;

      while (isspace(*it) && *it != '\0' && *it != '\n') {
         ++it;
      }

      if (*it == '#') {
         continue;
      }

      for (attribute = LINK_NUM, str1 = line; ;attribute++, str1 = NULL) {
         tok = strtok_r(str1, ",", &save_pt1);
         if (tok == NULL) {
             break;
         }

         switch (attribute) {
         case LINK_NUM: //parsing link number
            num = 0;
            if (sscanf(tok, "%d", &num) == EOF) {
               fprintf(stderr, "Error: Parsing link value failed.\n");
               goto failure;
            }
            links->conf[links->num].m_val = num;
            break;

         case LINK_NAME: //parsing link name
            links->conf[links->num].m_name = strdup(tok);
            if (!(links->conf[links->num].m_name)) {
               fprintf(stderr, "Error: Cannot parse LINK_NAME.\n");
               goto failure;
            }
            break;

         case LINK_UR_FIELD: //parsing UR_FIELD
            links->conf[links->num].m_ur_field = strdup(tok);
            if (!links->conf[links->num].m_ur_field) {
               fprintf(stderr, "Error: Cannot parse LINK_UR_FIELD.\n");
               goto failure;
            }
            break;

         case LINK_COL: //parsing line color
            num = 0;
            if (sscanf(tok, "%d", &num) == EOF) {
               fprintf(stderr, "Error: Parsing color failed.\n");
               goto failure;
            }
            links->conf[links->num].m_color = num;
            break;
         }
      }
      links->conf[links->num].m_id = links->num;
      links->num++;
      free(line);
      line = NULL;
      len = 0;
   }

   fclose(fp);

   if (line) {
      free(line);
   }

   printf(">Configuration success.\n");
   return 0;

failure:
   if (fp) {
      fclose(fp);
   }

   if (line) {
      free(line);
   }

   return 1;
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
int prepare_data(link_load_t *links)
{
   size_t i = 0, size;

   if (databuffer == NULL) {
      databuffer = calloc(4096, sizeof(char));
      if (databuffer == NULL) {
         return 0;
      }
      databuffer_size = 4096;
      header_len = 0;

      for (i = 0; i < links->num; i++) {
         if (!links->conf[i].m_name) {
            fprintf(stderr, "Error: No links names loaded.\n");
            return 0;
         }
         header_len += snprintf(databuffer + header_len, databuffer_size - header_len,
                                "%s-in-bytes,%s-in-flows,%s-in-packets,%s-out-bytes,%s-out-flows,%s-out-packets,",
                                 links->conf[i].m_name,links->conf[i].m_name,links->conf[i].m_name,
                                 links->conf[i].m_name,links->conf[i].m_name,links->conf[i].m_name);
      }
      databuffer[header_len - 1] = '\n';
   }

   size = header_len;
   for (i = 0; i < links->num; i++) {
      if (!stats) {
         fprintf(stderr, "Error: Cannot read from stats.\n");
         return 0;
      }
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
   struct sockaddr_un address;
   link_load_t *links = (link_load_t *) arg;

   int fd = socket(AF_UNIX, SOCK_STREAM, 0);
   if (fd < 0) {
      fprintf(stderr, "Error: Socket creation failed.\n");
      goto cleanup;
   }

   bzero(&address, sizeof(address));
   address.sun_family = AF_UNIX;
   strcpy(address.sun_path, DEF_SOCKET_PATH);
   unlink(DEF_SOCKET_PATH);

   if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
      fprintf(stderr, "Error: Bind failed.\n");
      goto cleanup;
   }

   /* changing permissions for socket so munin can read data from it */
   if (chmod(DEF_SOCKET_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0) {
      fprintf(stderr, "Error: Changing permissions failed.\n");
      goto cleanup;
   }

   if (listen(fd, 5) < 0) {
      fprintf(stderr, "Error: Listen failed.\n");
      goto cleanup;
   }

   soc_size = sizeof(clt);

   while (!stop) {
      client_fd = accept(fd, (struct sockaddr *) &clt, &soc_size);
      if (client_fd < 0) {
         fprintf(stderr, "Error: Accept failed.\n");
         continue;
      }

      if (prepare_data(links) > 0) {
         send_to_sock(client_fd, databuffer);
      } else {
         fprintf(stderr, "Error: Prepare data failed.\n");
         close(client_fd);
      }
   }

/* clean up */
cleanup:
   stop = 1;
   trap_terminate();
   if (fd >= 0) {
      close(fd);
   }

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
   link_load_t *links = NULL;

   pthread_t accept_thread;
   pthread_attr_t thrAttr;
   pthread_attr_init(&thrAttr);
   pthread_attr_setdetachstate(&thrAttr, PTHREAD_CREATE_DETACHED);

   /* return value for control of opening sockets and saving loop */
   int ret = 0;

   links = (link_load_t *) calloc(1, sizeof(link_load_t));
   if (!links) {
      fprintf(stderr, "Error while allocating memory for loaded configuration.\n");
      goto cleanup;
   }

   /* load links configuration file */
   if (load_links(CONFIG_PATH, links)) {
      fprintf(stderr, "Error loading configuration.\n");
      goto cleanup;
   }

   /* allocate memory for stats, based on loaded number of links */
   stats = (link_stats_t *) calloc(links->num + 1, sizeof(link_stats_t));
   if (!stats) {
      fprintf(stderr, "Error while allocating memory for stats.\n");
      goto cleanup;
   }

   // sort links unirec_fields
   qsort(links->conf, links->num, sizeof(link_conf_t), confcmp);

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
                        (void*) links);

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
            fprintf(stderr, "Error: data with wrong size received \
                           (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }
      /* get from what collecto data came and in what direction the flow
       * was comming */
      direction = ur_get(in_tmplt, in_rec, F_DIR_BIT_FIELD);
      /* save data according to information got by the code above */
      link_conf_t key, *found = NULL;
      key.m_val = ur_get(in_tmplt, in_rec, F_LINK_BIT_FIELD);
      found = bsearch(&key, links->conf, links->num, sizeof(link_conf_t), confcmp);
      if (found != NULL) {
         count_stats(found->m_id, direction, in_tmplt, in_rec);
      } else {
         count_stats(links->num, direction, in_tmplt, in_rec);
      }
   }

   pthread_cancel(accept_thread);
   /* **** Cleanup **** */
cleanup:
   if (databuffer) {
      free(databuffer);
   }

   if (in_tmplt) {
      ur_free_template(in_tmplt);
   }
   if (stats) {
      free(stats);
   }
   clear_conf_struct(links);
   pthread_attr_destroy(&thrAttr);
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   ur_finalize();
   return 0;
}
