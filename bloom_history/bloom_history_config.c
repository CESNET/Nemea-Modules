#include <errno.h>
#include <stdint.h>

#include <jansson.h>
#include <unirec/unirec.h>

#include "bloom.h"
#include "bloom_history.h"
#include "bloom_history_config.h"


void bloom_history_config_init(struct bloom_history_config* config)
{
   config->size = 0;
   config->id = NULL;
   config->api_url = NULL;
   config->bloom_entries = NULL;
   config->bloom_fp_error_rate = NULL;
   config->bloom_list = NULL;
   config->bloom_list_size = 0;
}

int bloom_history_config_add_record(struct bloom_history_config* config, uint32_t id, const char* api_url, 
                                    int32_t bloom_entries, double bloom_fp_error_rate)
{
   size_t new_size = config->size + 1;

   config->id = realloc(config->id, sizeof(*(config->id)) * new_size);
   config->api_url = realloc(config->api_url, sizeof(*(config->api_url)) * new_size);
   config->bloom_entries = realloc(config->bloom_entries, sizeof(*(config->bloom_entries)) * new_size);
   config->bloom_fp_error_rate = realloc(config->bloom_fp_error_rate, sizeof(*(config->bloom_fp_error_rate)) * new_size);
   if (!config->id
       || !config->api_url
       || !config->bloom_entries
       || !config->bloom_fp_error_rate) {
      bloom_history_config_free(config);
      return -2;
   }
   config->size = new_size;

   config->id[new_size-1] = id;
   // Store string copy
   config->api_url[new_size-1] = malloc((strlen(api_url)+1) * sizeof(*api_url));
   if (!config->api_url[new_size-1]) {
      return -3;
   }
   memcpy(config->api_url[new_size-1], api_url, strlen(api_url)+1);
   config->bloom_entries[new_size-1] = bloom_entries;
   config->bloom_fp_error_rate[new_size-1] = bloom_fp_error_rate;

   return 0;
}

void bloom_history_config_free(struct bloom_history_config* config)
{
   if (config->id) {
      free(config->id);
      config->id = NULL;
   }
   if (config->api_url) {
      for (size_t i = 0; i < config->size; i++) {
         if (config->api_url[i]) {
            free(config->api_url[i]);
            config->api_url[i] = 0;
         }
      }
      free(config->api_url);
      config->api_url = NULL;
   }
   if (config->bloom_entries) {
      free(config->bloom_entries);
      config->bloom_entries = NULL;
   }
   if (config->bloom_fp_error_rate) {
      free(config->bloom_fp_error_rate);
      config->bloom_fp_error_rate = NULL;
   }
   if (config->bloom_list) {
      for (size_t i = 0; i < config->bloom_list_size; i++) {
         if (config->bloom_list[i]) {
            bloom_free(config->bloom_list[i]);
            free(config->bloom_list[i]);
            config->bloom_list[i] = 0;
         }
      }
      free(config->bloom_list);
      config->bloom_list = NULL;
   }

   config->size = 0;
   config->bloom_list_size = 0;
}

int bloom_history_parse_config(const char* config_file, struct bloom_history_config *config)
{
   int error = 0;
   size_t max_id = 0;
   bloom_history_config_init(config);

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
      debug_print("bloom_history_parse_config id=%d\n", id);

      j_tmp = json_object_get(j_prefix, "api_url");
      ok &= json_is_string(j_tmp) && j_tmp;
      const char* api_url = json_string_value(j_tmp); // freed by json-c
      debug_print("bloom_history_parse_config api_url=%s\n", api_url);

      j_tmp = json_object_get(j_prefix, "bloom_entries");
      ok &= json_is_integer(j_tmp) && j_tmp;
      int32_t bloom_entries = json_integer_value(j_tmp);
      debug_print("bloom_history_parse_config bloom_entries=%d\n", bloom_entries);

      j_tmp = json_object_get(j_prefix, "bloom_fp_error_rate");
      ok &= json_is_real(j_tmp) && j_tmp;
      double bloom_fp_error_rate = json_real_value(j_tmp);
      debug_print("bloom_history_parse_config bloom_fp_error_rate=%f\n", bloom_fp_error_rate);

      if (!ok) {
         fprintf(stderr, "Error: bad config format\n");
         error = 1;
         goto cleanup;
      }

      error = bloom_history_config_add_record(config, id, api_url, bloom_entries, bloom_fp_error_rate);
      debug_print("bloom_history_config_add_record ret=%d\n", error);
      if (error) {
         goto cleanup;
      }
      if (id > max_id) {
         max_id = id;
      }
   }	

   if (config->size < 1) {
      fprintf(stderr, "Error: at least one network prefix has to be specified in configuration file\n");
      error = 1;
      goto cleanup;
   }

   // Allocate bloom filters on the right places
   config->bloom_list_size = max_id + 1;
   config->bloom_list = calloc(config->bloom_list_size, sizeof(*(config->bloom_list)));
   if (!config->bloom_list) {
      error = -42;
      goto cleanup;
   }
   for (size_t i = 0; i < config->size; i++) {
      uint32_t id = config->id[i];
      config->bloom_list[id] = calloc(1, sizeof(struct bloom));
      if (!config->bloom_list[id]) {
         error = -43;
         goto cleanup;
      }
      if (bloom_init(config->bloom_list[id], config->bloom_entries[i], config->bloom_fp_error_rate[i])) {
         error = -44;
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
