/**
 * \file prefix_tags.c
 * \brief Tags unirec messages based on src_ip beloning to one of the configured prefixes
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "fields.h"
#include "prefix_tags.h"
#include "prefix_tags_config.h"
#include "prefix_tags_functions.h"


UR_FIELDS (
   ipaddr SRC_IP,
   ipaddr DST_IP,
   uint32 PREFIX_TAG,
   uint32 PREFIX_TAG_DST
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("prefix_tags","This module adds PREFIX_TAG field to the output acording to configured ip prefixes.", 1, 1)

#define MODULE_PARAMS(PARAM) \
   PARAM('c', "config", "Configuration file.", required_argument, "string") \
   PARAM('d', "dst", "Use only DST_IP field for prefix matching (default is both SRC_IP and DST_IP).", no_argument, "none") \
   PARAM('s', "src", "Use only SRC_IP field for prefix matching (default is both SRC_IP and DST_IP).", no_argument, "none") \
   PARAM('b', "both", "Tag both SRC_IP and DST_IP", no_argument,"none")

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

int CHECK_SRC_IP = 1;
int CHECK_DST_IP = 1;
int CHECK_BOTH = 0;


int prefix_tags(ipps_context_t *config) {
   int error = 0;
   uint32_t prefix_tag;
   uint32_t prefix_tag_dst;
   const void *data_in = NULL;
   uint16_t data_in_size;
   void *data_out = NULL;
   ur_template_t *template_in = ur_create_input_template(INTERFACE_IN, "", NULL); // Gets updated on first use by TRAP_RECEIVE anyway
   ur_template_t *template_out = NULL; // Some modules have porblems with changing templates, so it is better to set initial output template to the template that comes in first - see update_output_format

   if (template_in == NULL) {
      error = -1;
      goto cleanup;
   }

   while (stop == 0) {
      int recv_error = TRAP_RECEIVE(INTERFACE_IN, data_in, data_in_size, template_in);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(recv_error, continue, error = -2; goto cleanup)
      if (recv_error == TRAP_E_FORMAT_CHANGED) {
         // Copy format to output interface and add PREFIX_TAG
	 error = update_output_format(template_in, data_in, &template_out, &data_out);
         if (error) {
            goto cleanup;
         }
         if (DEBUG) {
            ur_print_template(template_out);
            ur_print_template(template_in);
         }
      }

      if (data_in_size <= 1) { // End of stream
         goto cleanup;
      }

      ip_addr_t src_ip = ur_get(template_in, data_in, F_SRC_IP);
      ip_addr_t dst_ip = ur_get(template_in, data_in, F_DST_IP);
      prefix_tag = 0;
      prefix_tag_dst = 0;
      int src_res = 0;
      int dst_res = 0;

      if (CHECK_SRC_IP || CHECK_BOTH){
      	src_res = is_from_configured_prefix(config, &src_ip, &prefix_tag);
      }
      if ((!src_res && CHECK_DST_IP) || CHECK_BOTH){
      	dst_res = is_from_configured_prefix(config, &dst_ip, &prefix_tag_dst);
      }

      if (src_res || dst_res) {
         debug_print("tagging %d\n", prefix_tag);
         // data_out should have the right size since TRAP_E_FORMAT_CHANGED _had_ to be returned before getting here
         ur_copy_fields(template_out, data_out, template_in, data_in);
         // Set PREFIX_TAG field
	 if (CHECK_BOTH == 0) {
         	ur_set(template_out, data_out, F_PREFIX_TAG, (prefix_tag!=0)?prefix_tag:prefix_tag_dst);
	 } else {
		ur_set(template_out, data_out, F_PREFIX_TAG, prefix_tag);
	        ur_set(template_out, data_out, F_PREFIX_TAG_DST, prefix_tag_dst);	
	 }
         uint16_t data_out_size = ur_rec_size(template_out, data_out);
         debug_print("data_out_size %d\n", data_out_size);
         int  send_error = trap_send(INTERFACE_OUT, data_out, data_out_size);
         debug_print("send_error %d\n", send_error);
         TRAP_DEFAULT_SEND_ERROR_HANDLING(send_error, continue, error = -3; goto cleanup)
      }
   }

cleanup:
   if (data_out != NULL) {
      ur_free_record(data_out);
   }

   ur_free_template(template_in);
   ur_free_template(template_out);
   ur_finalize();

   return error;
}

int main(int argc, char **argv)
{
   int error = 0;
   signed char opt;

   ipps_context_t *config = NULL;

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   errno = 0; // reset errno before signal handler setup
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'c':
         error = parse_config(optarg, &config);
         debug_print("parse_config ret %d\n", error);
         if (error != 0) {
            fprintf(stderr, "Parsing configuration file failed (%s).\n", optarg);
            error = -1;
            goto cleanup;
         }
         break;
      case 'd':
         CHECK_SRC_IP = 0;
         break;
      case 's':
         CHECK_DST_IP = 0;
         break;
      case 'b':
	 CHECK_BOTH = 1;
	 break;
      }
   }

   error = prefix_tags(config);
   debug_print("prefix_tags ret %d\n", error);

cleanup:
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   ipps_destroy(config);

   return error;
}
