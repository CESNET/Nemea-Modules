#include <errno.h>
#include <stdint.h>

#include <libtrap/jansson.h>
#include <unirec/unirec.h>

#include "prefix_tags.h"
#include "prefix_tags_config.h"


void tags_config_init(struct tags_config *config) {
   config->size = 0;
   config->id = NULL;
   config->ip_prefix_length = NULL;
   config->ip_prefix = NULL;
}

int tags_config_add_record(struct tags_config *config, uint32_t id, ip_addr_t ip_prefix, uint32_t ip_prefix_length)
{
   size_t new_size = config->size + 1;

   config->id = realloc(config->id, sizeof(*(config->id)) * new_size);
   config->ip_prefix = realloc(config->ip_prefix, sizeof(*(config->ip_prefix)) * new_size);
   config->ip_prefix_length = realloc(config->ip_prefix_length, sizeof(*(config->ip_prefix_length)) * new_size);
   if (!config->id || !config->ip_prefix || !config->ip_prefix_length) {
      return -2;
   }
   config->size = new_size;


   config->id[new_size-1] = id;
   config->ip_prefix[new_size-1] = ip_prefix;
   config->ip_prefix_length[new_size-1] = ip_prefix_length;

   return 0;
}

void tags_config_free(struct tags_config *config)
{
   if (config->id) {
      free(config->id);
      config->id = NULL;
   }
   if (config->ip_prefix_length) {
      free(config->ip_prefix_length);
      config->ip_prefix_length = NULL;
   }
   if (config->ip_prefix) {
      free(config->ip_prefix);
      config->ip_prefix = NULL;
   }
   config->size = 0;
}

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

int parse_config(const char *config_file, struct tags_config *config)
{
   int error = 0;

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

      error = tags_config_add_record(config, id, ip_prefix, ip_prefix_length);
      debug_print("tags_config_add_record ret %d\n", error);
      if (error) {
         goto cleanup;
      }
   }	

cleanup:
   fclose(fp);
   if (j_root) {
      json_decref(j_root); // decrement ref-count to free whole j_root
   }

   return error;
}
