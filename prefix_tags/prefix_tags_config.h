#ifndef __PREFIX_TAGS_CONFIG_H_
#define __PREFIX_TAGS_CONFIG_H_
#define _GNU_SOURCE

#include <stdint.h>

#include <unirec/unirec.h>


struct tags_config {
  size_t size;
  uint32_t *id;
  ip_addr_t *ip_prefix;
  uint32_t *ip_prefix_length;
};

void tags_config_init(struct tags_config *config);

int tags_config_add_record(struct tags_config *config, uint32_t id, ip_addr_t ip_prefix, uint32_t ip_prefix_length);

void tags_config_free(struct tags_config *config);

int tags_parse_ip_prefix(const char *ip_prefix, ip_addr_t *addr, uint32_t *prefix_length);

int parse_config(const char *config_file, struct tags_config *config);


#endif // __PREFIX_TAGS_CONFIG_H_
