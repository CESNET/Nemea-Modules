#include <errno.h>
#include <stdint.h>

#include <libtrap/jansson.h>
#include <unirec/unirec.h>

#include "prefix_tags.h"
#include "prefix_tags_config.h"


int tags_parse_ip_prefix(const char *ip_prefix, ip_addr_t *addr, uint32_t *prefix_length)
{
   long prefix_length_l;
   char *prefix_slash = strchr(ip_prefix, '/');

   if (prefix_slash == NULL) {
      return -1;
   }
   *((char *)prefix_slash) = '\0'; // Don't do tihs at home kids

   if (!ip_from_str(ip_prefix, addr)) {
      return -1;
   }

   prefix_length_l = strtol(prefix_slash + 1, NULL, 10);
   if (errno != 0) {
      return -1;
   }
   *prefix_length = prefix_length_l;
   if (*prefix_length != prefix_length_l) {
      return -1;
   }

   return 0;
}

/** Dealloc ipps_network_list_t
 * Dealloc struct ipps_network_list_t
 * @param[in] network_list Pointer to network_list structure
 * @return void
 */
void destroy_networks(ipps_network_list_t *network_list)
{
   int index;
   for (index = 0; index < network_list->net_count; index++) {
      free(network_list->networks[index].data);
   }

   free(network_list->networks);
   free(network_list);
}

int parse_config(const char *config_file, ipps_context_t **config)
{
   int error = 0;
   int struct_count = 50;

   // Alloc memory for networks structs, if malloc fails return NULL
   ipps_network_t *networks = malloc(struct_count * sizeof(ipps_network_t));
   if (networks == NULL) {
      fprintf(stderr, "ERROR allocating memory for network structures\n");
      return -1;
   }

   ipps_network_list_t *netlist = malloc(sizeof(ipps_network_list_t));
   if (netlist == NULL) {
      fprintf(stderr, "ERROR allocating memory for network list\n");
      free(networks);
      return -1;
   }

   // Parse JSON
   FILE* fp = fopen(config_file, "r");
   if (fp == NULL) {
      fprintf(stderr, "Error: %s\n", strerror(errno));
      return -1;
   }
   json_error_t* j_error = NULL;
   json_t* j_root = json_loadf(fp, JSON_REJECT_DUPLICATES, j_error);
   if (j_root == NULL) {
      if (j_error != NULL) {
         fprintf(stderr, "Error: parsing config on line %d: %s\n", j_error->line, j_error->text);
      } else {
         fprintf(stderr, "Error: unable to parse config file '%s'\n", config_file);
      }
      error = 1;
      goto cleanup;
   }
   if (!json_is_array(j_root)) {
      fprintf(stderr, "Error: bad JSON format\n");
      error = 1;
      goto cleanup;
   }

   // Populate config struct
   for (size_t i = 0; i < json_array_size(j_root); i++) {
      int ok = 1;
      json_t* j_prefix = json_array_get(j_root, i);
      json_t* j_tmp;

      j_tmp = json_object_get(j_prefix, "id");
      ok &= json_is_integer(j_tmp);
      uint32_t id = json_integer_value(j_tmp);
      debug_print("tags_parse_config id=%d\n", id);

      j_tmp = json_object_get(j_prefix, "ip_prefix");
      ok &= json_is_string(j_tmp) && j_tmp;
      const char* ip_prefix_c = json_string_value(j_tmp); // freed by json-c
      debug_print("tags_parse_config ip_prefix=%s\n", ip_prefix_c);

      if (!ok) {
         fprintf(stderr, "Error: bad config format\n");
         error = 1;
         goto cleanup;
      }

      ip_addr_t ip_prefix;
      uint32_t ip_prefix_length;
      error = tags_parse_ip_prefix(ip_prefix_c, &ip_prefix, &ip_prefix_length);
      debug_print("tags_parse_ip_prefix ip_prefix=%s ret=%d\n", ip_prefix_c, error);
      if (error) {
         fprintf(stderr, "Malformed IP prefix %s in the configuration file.\n", ip_prefix_c);
         goto cleanup;
      }

      // If limit is reached alloc new memory
      if (i >= struct_count) {
          struct_count += 10;
          // If realloc fails return NULL
          if ((networks = realloc(networks, struct_count * sizeof(ipps_network_t))) == NULL) {
              fprintf(stderr, "ERROR in reallocating network structure\n");
              error = 1;
              goto cleanup;
          }
      }

      networks[i].addr = ip_prefix;
      networks[i].mask = ip_prefix_length;
      networks[i].data = malloc(sizeof(id));
      if (networks[i].data == NULL) {
         fprintf(stderr, "ERROR in allocating memory for identifier\n");
         error = 1;
         goto cleanup;
      }

      networks[i].data_len = sizeof(id);
      *((uint32_t *) networks[i].data) = id;
   }
   netlist->networks = networks;
   netlist->net_count = json_array_size(j_root);

   (*config) = ipps_init(netlist);

cleanup:
   destroy_networks(netlist);
   fclose(fp);
   if (j_root) {
      json_decref(j_root); // decrement ref-count to free whole j_root
   }

   return error;
}
