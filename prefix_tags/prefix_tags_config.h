#ifndef __PREFIX_TAGS_CONFIG_H_
#define __PREFIX_TAGS_CONFIG_H_
#define _GNU_SOURCE

#include <stdint.h>

#include <unirec/unirec.h>
#include <unirec/ip_prefix_search.h>

int tags_parse_ip_prefix(const char *ip_prefix, ip_addr_t *addr, uint32_t *prefix_length);

int parse_config(const char *config_file, ipps_context_t **config);


#endif // __PREFIX_TAGS_CONFIG_H_
