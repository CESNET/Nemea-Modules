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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdlib.h>
#include "fields.h"
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>
#include <sysrepo.h>
#include <sysrepo/values.h>

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
#define XPATH_MAX_LEN 100

static volatile int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

typedef struct link_stats {
   volatile uint64_t flows_in; /*!uint64_t incomming flows */
   volatile uint32_t packets_in; /*!uint32_t incomming packets */
   volatile uint64_t bytes_in; /*!uint64_t incomming bytes */
   volatile uint64_t flows_out; /*!uint64_t outgoing flows */
   volatile uint32_t packets_out; /*!uint32_t outgoing packets */
   volatile uint64_t bytes_out; /*!uint64_t outgoing bytes */
} link_stats_t;

typedef struct link_conf {
   int         m_num;        /*!int number of link*/
   char        *m_name;      /*!string name of link*/
   char        *m_ur_field;  /*!string link bit field of link*/
   uint32_t    m_color;      /*!int represents hex value of link's color*/
} link_conf_t;

/* structure used for loading configuration and passing it
 * to the thread */
typedef struct link_loaded {
   link_conf_t    *conf;     /*!struct of loaded links configuration */
   link_stats_t   *stats;    /*!array of link_stats_t structure for statistics */
   size_t         num;       /*!size_t number of loaded links */
} link_load_t;

/* For locking access to links struct */
pthread_mutex_t lock_links;

/**
 * Clears all but the initial pointer of link_load_t struct.
 */
void clear_conf_struct(link_load_t *links)
{
   int i;
   /* don't clear when it's empty */
   if (!links) {
      return;
   }
   pthread_mutex_lock(&lock_links);
   if (links->conf) {
      for (i = 0; i < links->num; i++) {
         if (links->conf[i].m_name) {
            free(links->conf[i].m_name);
            links->conf[i].m_name = NULL;
         }
         if (links->conf[i].m_ur_field) {
            free(links->conf[i].m_ur_field);
            links->conf[i].m_ur_field = NULL;
         }
      }
      free(links->conf);
      links->conf = NULL;
      if(links->stats){
         free(links->stats);
         links->stats = NULL;
      }
   }
   pthread_mutex_unlock(&lock_links);
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
   /* every time somebody connects to socket header and data is created again \
      could be improved in the future for header to change only if config changes. */
   size_t i = 0, size = 0;
   databuffer_size = 0;
   header_len = 0;

   /* determining size of the buffer needed for output text */
   pthread_mutex_lock(&lock_links);
   for (i = 0; i < links->num; i++) {
      databuffer_size += snprintf(NULL, 0,
                             "%s-in-bytes,%s-in-flows,%s-in-packets,%s-out-bytes,%s-out-flows,%s-out-packets,\n%"
                             PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32",",
                             links->conf[i].m_name,links->conf[i].m_name,links->conf[i].m_name,
                             links->conf[i].m_name,links->conf[i].m_name,links->conf[i].m_name,
                             links->stats[i].bytes_in, links->stats[i].flows_in, links->stats[i].packets_in,
                             links->stats[i].bytes_out, links->stats[i].flows_out, links->stats[i].packets_out);
   }
   pthread_mutex_unlock(&lock_links);

   /* freeing any previous databuffer */
   if (databuffer) {
      free(databuffer);
   }

   databuffer = NULL;
   databuffer = calloc(databuffer_size + 2, sizeof(char)); /* the '+ 2' is for last \n and \0 */
   if (databuffer == NULL) {
      fprintf(stderr, "prepare_data: Cannot allocate memory for output data string.\n");
      return 0;
   }

   pthread_mutex_lock(&lock_links);
   for (i = 0; i < links->num; i++) {
      header_len += snprintf(databuffer + header_len, databuffer_size - header_len,
                             "%s-in-bytes,%s-in-flows,%s-in-packets,%s-out-bytes,%s-out-flows,%s-out-packets,",
                              links->conf[i].m_name,links->conf[i].m_name,links->conf[i].m_name,
                              links->conf[i].m_name,links->conf[i].m_name,links->conf[i].m_name);
   }
   databuffer[header_len - 1] = '\n';

   size = header_len;
   for (i = 0; i < links->num; i++) {
      size += snprintf(databuffer + size, databuffer_size - size, "%"
                       PRIu64",%" PRIu64",%" PRIu32",%" PRIu64",%" PRIu64",%" PRIu32",",
                       links->stats[i].bytes_in, links->stats[i].flows_in, links->stats[i].packets_in,
                       links->stats[i].bytes_out, links->stats[i].flows_out, links->stats[i].packets_out);
   }
   pthread_mutex_unlock(&lock_links);
   databuffer[size - 1] = '\n';
   databuffer[size] = '\0';

   return size;
}

/**
 * Sending prepared data - string to open socket.
 */
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

/**
 * Waiting for clients to connect to unix socket.
 */
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
   if (fd) {
      close(fd);
   }

   pthread_exit(0);
}

/*
 * Adds data to global array of link_stats_t structures "stats[]".
 */
void count_stats (uint64_t link,
                  uint8_t direction,
                  ur_template_t *in_tmplt,
                  const void *in_rec,
                  link_stats_t *stats
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

/*
 * Getting number of links from sysrepo.
 */
static int get_links_number(sr_session_ctx_t *session, const char *module_name, size_t *num)
{
   sr_val_t *values = NULL;
   int ret = SR_ERR_OK;
   char select_xpath[XPATH_MAX_LEN];
   snprintf(select_xpath, XPATH_MAX_LEN, "/%s:links/*", module_name);

   ret = sr_get_items(session, select_xpath, &values, num);
   if (SR_ERR_OK != ret) {
       printf("Error by sr_get_items: %s\n", sr_strerror(ret));
       return ret;
   }
   printf("Number of links in configuration is: %zu\n", *num);

   sr_free_values(values, *num);
   return ret;
}

/*
 * Loading configuration of one leaf of leaf list to stats[i] from sysrepo.
 */
static int get_config(sr_session_ctx_t *session, const char *module_name, link_load_t *links)
{
   sr_val_t *value = NULL;
   sr_val_iter_t *iter = NULL;
   int ret = 0, i = 0;
   char select_xpath[XPATH_MAX_LEN];

   /* getting link name */
   snprintf(select_xpath, XPATH_MAX_LEN, "/%s:links/link/name", module_name);
   ret = sr_get_items_iter(session, select_xpath, &iter);
   if (SR_ERR_OK != ret) {
      return 1;
   }

   while (sr_get_item_next(session, iter, &value) == SR_ERR_OK){
      if(value->type == SR_STRING_T){
         links->conf[i].m_name = strdup(value->data.string_val);
      }
      sr_free_val(value);
      i++;
   }
   sr_free_val_iter(iter);

   /* getting link color */
   i = 0;
   snprintf(select_xpath, XPATH_MAX_LEN, "/%s:links/link/color", module_name);
   ret = sr_get_items_iter(session, select_xpath, &iter);
   if (SR_ERR_OK != ret) {
      return 1;
   }

   while (sr_get_item_next(session, iter, &value) == SR_ERR_OK){
   if(value->type == SR_STRING_T){
      uint32_t hex;
      sscanf(value->data.string_val, "%"SCNx32, &hex);
      links->conf[i].m_color = hex;
      }
   sr_free_val(value);
           i++;
   }
   sr_free_val_iter(iter);

   return ret;
}

/*
 * Loading whole configuration from sysrepo to stats[].
 */
int load_links(sr_session_ctx_t *session, const char *module_name, link_load_t *links)
{
   int ret = 0;

   ret = get_links_number(session, module_name, &(links->num));
   if (SR_ERR_OK != ret) {
      fprintf(stderr, "load_links: Couldn't retrieve number of links.\n");
      return ret;
   }

   links->conf = (link_conf_t *) calloc(links->num, sizeof(link_conf_t));
   if (links->conf == NULL) {
      fprintf(stderr, "load_links: Failed to initialise configuration memory.\n");
      return 1;
   }

   /* allocate memory for stats, based on loaded number of links */
   links->stats = (link_stats_t *) calloc(links->num, sizeof(link_stats_t));
   if (!links->stats) {
      fprintf(stderr, "Error while allocating memory for stats.\n");
      return 1;
   }

   get_config(session, module_name, links);
   return 0;
}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *change_flag)
{
   link_load_t *links = (link_load_t *) change_flag;
   int ret = 0;
   clear_conf_struct(links);

   switch (event) {
   case SR_EV_VERIFY:
      fprintf(stdout, "Verifying configuration.\n");
      return 0;
   case SR_EV_APPLY:
      printf("New config has been loaded from sysrepo.\n");
      break;
   case SR_EV_ABORT:
   default:
      fprintf(stderr, "Could not verify configuration.\n");
      return 1;
   }

   pthread_mutex_lock(&lock_links);
   ret = load_links(session, module_name, links);
   pthread_mutex_unlock(&lock_links);
   if (SR_ERR_OK != ret) {
      fprintf(stderr, "Error while loading config from sysrepo.\n");
      return ret;
   }

   return SR_ERR_OK;
}

int main(int argc, char **argv)
{
   signed char opt;
   ur_template_t *in_tmplt = NULL;
   link_load_t *links = NULL;

   sr_conn_ctx_t *connection = NULL;
   sr_session_ctx_t *session = NULL;
   sr_subscription_ctx_t *subscription = NULL;
   char *module_name = "link-traffic";

   pthread_t accept_thread;
   pthread_attr_t thrAttr;
   pthread_attr_init(&thrAttr);
   pthread_attr_setdetachstate(&thrAttr, PTHREAD_CREATE_DETACHED);

   /* return value for control of opening sockets and saving loop */
   int ret = 0;

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

   /* connect to sysrepo */
   ret = sr_connect("link_traffic", SR_CONN_DEFAULT, &connection);
   if (SR_ERR_OK != ret) {
      fprintf(stderr, "Error: sr_connect to sysrepo: %s\n", sr_strerror(ret));
      goto cleanup;
   }

   /* start session */
   ret = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
   if (SR_ERR_OK != ret) {
      fprintf(stderr, "Error: sysrepo sr_session_start: %s\n", sr_strerror(ret));
      goto cleanup;
   }

   links = (link_load_t *) calloc(1, sizeof(link_load_t));
   if (!links) {
      fprintf(stderr, "Error: allocating memory for loaded configuration.\n");
      goto cleanup;
   }

   /* load link configuration from sysrepo */
   ret = load_links(session, module_name, links);
   if (SR_ERR_OK != ret) {
      fprintf(stderr, "Error while loading config from sysrepo.\n");
      goto cleanup;
   }

   /* set up subscription to sysrepo */
   ret = sr_module_change_subscribe(session, module_name, module_change_cb, links,
           0, SR_SUBSCR_DEFAULT, &subscription);
   if (SR_ERR_OK != ret) {
       fprintf(stderr, "Error: sysrepo sr_module_change_subscribe: %s\n", sr_strerror(ret));
       goto cleanup;
   }

   //TODO thread locking for safe access to links structure

   ret = pthread_create(&accept_thread,
                        &thrAttr,
                        accept_clients,
                        (void *) links);

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
      /* get from what collector data came and in what direction the flow
       * was comming */
      link_index = __builtin_ctzll(ur_get(in_tmplt, in_rec, F_LINK_BIT_FIELD));
      direction = ur_get(in_tmplt, in_rec, F_DIR_BIT_FIELD);
      /* save data according to information got by the code above */
      pthread_mutex_lock(&lock_links);
      count_stats(link_index, direction, in_tmplt, in_rec, links->stats);
      pthread_mutex_unlock(&lock_links);
   }
   stop = 1;
   pthread_join(accept_thread, NULL);
   /* **** Cleanup **** */
cleanup:
   if (databuffer) {
      free(databuffer);
   }
   if (in_tmplt) {
      ur_free_template(in_tmplt);
   }
   /* sysrepo cleanup */
   if (NULL != subscription) {
      sr_unsubscribe(session, subscription);
   }
   if (NULL != session) {
      sr_session_stop(session);
   }
   if (NULL != connection) {
      sr_disconnect(connection);
   }

   clear_conf_struct(links);
   if (links){
      free(links);
   }
   pthread_attr_destroy(&thrAttr);
   TRAP_DEFAULT_FINALIZATION()
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   ur_finalize();
   return 0;
}
