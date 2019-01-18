#ifndef __BLOOM_HISTORY_CONFIG_H_
#define __BLOOM_HISTORY_CONFIG_H_
#define _GNU_SOURCE

#include <stdint.h>

#include <unirec/unirec.h>

#include "bloom.h"


struct bloom_history_config {
   size_t size;
   uint32_t *id;
   char** api_url;
   int32_t *bloom_entries;
   double *bloom_fp_error_rate;
   // TODO some explanation
   struct bloom **bloom_list;
   size_t bloom_list_size;
};


void bloom_history_config_init(struct bloom_history_config *config);

int bloom_history_config_add_record(struct bloom_history_config *config, uint32_t id,
                                    const char* api_url, int32_t bloom_entries,
                                    double bloom_fp_error_rate);

void bloom_history_config_free(struct bloom_history_config *config);

int bloom_history_parse_config(const char *config_file, struct bloom_history_config *config);


#endif // __BLOOM_HISTORY_CONFIG_H_
