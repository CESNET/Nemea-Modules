#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <unirec/unirec.h>

#include "prefix_tags.h"
#include "prefix_tags_config.h"
#include "prefix_tags_functions.h"


int update_output_format(ur_template_t *template_in, const void *data_in, ur_template_t **template_out, void **data_out)
{
   // Copy input template to output template
   char* template_in_str = ur_template_string(template_in);
   if (template_in_str == NULL) {
      return -1;
   }
   if (*template_out != NULL) {
      ur_free_template(*template_out);
   }
   *template_out = ur_create_template_from_ifc_spec(template_in_str);
   free(template_in_str);
   if (*template_out == NULL) {
      return -1;
   }

   // Add PREFIX_TAG field
   *template_out = ur_expand_template("uint32 PREFIX_TAG", *template_out);
   if (*template_out == NULL) {
      return -1;
   }
   if (ur_set_output_template(INTERFACE_OUT, *template_out) != UR_OK) {
      return -1;
   }

   // Reallocate output buffer
   if (ur_rec_varlen_size(template_in, data_in) != 0) {
      fprintf(stderr, "Error: Recieved input template with variable sized fields - this is currently not supported.\n");
      return -1;
   }
   if (*data_out != NULL) {
      ur_free_record(*data_out);
   }
   *data_out = ur_create_record(*template_out, 0); // Dynamic fields are currently not supported
   if (*data_out == NULL) {
      return -1;
   }

   return 0;
}

int is_from_prefix(ip_addr_t *ip, ip_addr_t *protected_prefix, int32_t protected_prefix_length)
{
   // Both IPv4
   if(ip_is4(ip) && ip_is4(protected_prefix)) {
      uint32_t mask = 0xffffffff << (32 - protected_prefix_length);
      return (ip_get_v4_as_int(ip) & mask) == (ip_get_v4_as_int(protected_prefix) & mask);
   }
   // Both IPv6
   if (ip_is6(ip) && ip_is6(protected_prefix)) {
      int bytes_match;

      // Compare whole bytes
      bytes_match = memcmp((const char *) ip, (const char *) protected_prefix, protected_prefix_length / 8) == 0;

      // Compare remaining byte
      if (bytes_match && protected_prefix_length % 8 != 0) {
         int byte_index = protected_prefix_length / 8;
         uint8_t mask = 0xff << (8 - (protected_prefix_length % 8));

         return bytes_match && ((ip->bytes[byte_index] & mask) == (protected_prefix->bytes[byte_index] & mask));
      }

      return bytes_match;
   }

   return 0;
}

int is_from_configured_prefix(ipps_context_t *config, ip_addr_t *ip, uint32_t *prefix_tag) {
   uint32_t **data;

   int result = ipps_search(ip, config, (void ***) &data);

   if (result > 0) {
      *prefix_tag = *data[0];
      return result;
   } else {
      return 0;
   }
}

