/**
 * \file anonymizer.c
 * \brief Module for anonymizing incoming flow records.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \author Zdenek Rosa <rosazden@fit.cvut.cz>
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2013-2018 CESNET
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


#include "anonymizer.h"
#include "panonymizer.h"
#include "fields.h"
#include <nemea-common.h>
#include <regex.h>

#define IP_V6_SIZE 16           // 128b or 16B is size of IP address version 6
#define SECRET_KEY_FILE "secret_key.txt"   // File with secret key
#define SECRET_KEY_MAX_SIZE 67             // Max length of secret key

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("anonymizer","",1,1)

// Description is constructed at run-time at the beginning of main() (list of supported fields is filled in)
#define MODULE_DESCRIPTION_TEMPLATE "Module for anonymizing flow records. Anonymizes IP addresses in the following fields:\n"\
     "    %s\n"\
     "If a field is of 'string' type, IP address represenation is searched in the string and replaced by its anonymized version."

#define MODULE_PARAMS(PARAM) \
   PARAM('k', "key", "Specify secret key, the key must be 32 characters long string or 32B sized hex string starting with 0x", required_argument, "string") \
   PARAM('f', "file", "Specify file containing secret key, the key must be 32 characters long string or 32B sized hex string starting with 0x", required_argument, "string") \
   PARAM('M', "murmur", "Use MurmurHash3 instead of Rijndael cipher.", no_argument, "none") \
   PARAM('d', "de-anonym", "Switch to de-anonymization mode.", no_argument, "none")

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

const char *anon_field_names[] = {"SRC_IP", "DST_IP", "SIP_CALLED_PARTY", "SIP_CALLING_PARTY", "SIP_CALL_ID", "SIP_REQUEST_URI", "SIP_VIA"};
#define ANON_FIELDS_COUNT (sizeof(anon_field_names) / sizeof(anon_field_names[0]))

ur_field_id_t anon_fields[ANON_FIELDS_COUNT]; // list of IDs of fields present in input template
int anon_fields_cnt = 0; // number of valid field IDs in anon_fields


/**
 * \brief Hash used as PRNG
 *        This function is from MurmurHash3.
 *        https://code.google.com/p/smhasher/wiki/MurmurHash3
 * \param key      Pointer to data from which will be computed hash.
 * \param key_size Size of data.
 * \return 32bit hash value.
 */
inline uint32_t hash_div8(const char *key, int32_t key_size)
{
   uint32_t c1 = 5333;
   uint32_t c2 = 7177;
   uint32_t r1 = 19;
   uint32_t m1 = 11117;
   uint32_t n1 = 14011;
   uint64_t h = 42;
   uint64_t *k_ptr = (uint64_t *) key;
   uint64_t k;
   uint32_t rep = key_size / 8;
   uint32_t i;

   for (i = 0; i < rep; i++) {
      k = *(k_ptr + i);
      k *= c1;
      k = ROTL64(k, r1);
      k *= c2;
      h ^= k;
      h = ROTL64(h, r1);
      h = h * m1 + n1;
   }

   h ^= h >> 33;
   h *= 0xff51afd7ed558ccd;
   h ^= h >> 33;
   h *= 0xc4ceb9fe1a85ec53;
   h ^= h >> 33;

   return (uint32_t) h;
}


/** \brief Initialize anonymizer
 * Initialize anonymizer with key included in file.
 * \param[in] secret_file Name of the file containing secret key.
 * \param[in] init_key Pointer to 32B free memory.
 * \return 1 if succes, 0 if not success.
 */
int init_from_file(char *secret_file, uint8_t *init_key)
{
   char secret_key[SECRET_KEY_MAX_SIZE];
   int key_end;
   FILE *fp;

   // Open file with secret key
   if ((fp = fopen(secret_file, "rb")) == NULL) {
      fprintf(stderr, "Error: Could not open file with secret key.\n");
      return 0;
   }

   // Reads secret key
   if (!fgets(secret_key, SECRET_KEY_MAX_SIZE, fp)) {
      fprintf(stderr, "Error: Error occured while reading the key.\n");
      fclose(fp);
      return 0;
   }
   fclose(fp);

   // Remove trailing whitespaces from secret key
   key_end = strlen(secret_key) - 1;
   while (isspace(secret_key[key_end])) {
      secret_key[key_end] = 0;
      key_end--;
   }

   // Parse secret key and initialize anonymizer
   if (ParseCryptoPAnKey(secret_key, init_key)) {
      PAnonymizer_Init(init_key);
      return 1;
   }

   return 0;
}

/** \brief Anonymize IP in static UniRec field
 * Anonymize source and destination IP in Unirec using Crypto-PAn libraries
 * \param[in-out] field_ptr  Pointer to Unirec string which is to be annonymized.
 * \param[in]     mode       Anonymizer mode (ANONYMIZATION or DEANONYMIZATION).
 * \return        void
*/
void ip_anonymize(void *field_ptr, uint8_t mode)
{
   uint32_t *ip_v4_ptr, ip_v4_anon;
   uint64_t *ip_v6_ptr, ip_v6_anon[2] = {0};

   /* Differentiate IPv4 and IPv6 */
   if (ip_is4(field_ptr)) {
      ip_v4_ptr = (uint32_t *) ip_get_v4_as_bytes(field_ptr);
      if (mode == ANONYMIZATION) {
         ip_v4_anon = anonymize(ntohl(*ip_v4_ptr));
      } else {
         ip_v4_anon = deanonymize(ntohl(*ip_v4_ptr));
      }

      *ip_v4_ptr = htonl(ip_v4_anon);
   } else {
      ip_v6_ptr = (uint64_t *) field_ptr;
      if (mode == ANONYMIZATION) {
         anonymize_v6(ip_v6_ptr, ip_v6_anon);
      } else {
         deanonymize_v6(ip_v6_ptr, ip_v6_anon);
      }

      memcpy(ip_v6_ptr, ip_v6_anon, IP_V6_SIZE);
   }
}

/** \brief Anonymize IP in dynamic UniRec field
 * Anonymize dynamic fields with character representation of IPv4 or IPv6
 * \param[in] field_ptr  Pointer to Unirec string which is to be annonymized.
 * \param[in] field_len  Legth of the dynamic field.
 * \param[in] mode       Anonymizer mode (ANONYMIZATION or DEANONYMIZATION).
 * \param[in] regex_IPV4 Compiled regular expression to match IPv4.
 * \param[in] regex_IPV6 Compiled regular expression to match IPv6.
 * \return    char*      Anonymized string or NULL if there is nothing to be annonymized.
*/
char *string_anonymize(void *field_ptr, uint32_t field_len, uint8_t mode, regex_t regex_IPV4, regex_t regex_IPV6)
{
#define OCCURENCES 2
   int reti;
   regmatch_t ip[OCCURENCES]; /* looking for 1 match, according to man regexec() need array of N+1 size */
   ip_addr_t tmp_ip;
   char *output = NULL;
   char *field = (char *) field_ptr;

   /* Temporarily end string with '\0' */
   char backup = field[field_len];
   field[field_len] = '\0';

   /* Check whether in field exists IPv4 or IPv6 address in string form */
   reti = regexec(&regex_IPV4, field, OCCURENCES, ip, 0);
   if (reti == REG_NOMATCH) {
      reti = regexec(&regex_IPV6, field, OCCURENCES, ip, 0);
      if (reti == REG_NOMATCH) {
         field[field_len] = backup;
         return output;
      }
   }

   /* Temporarily end IP address with \0 */
   char backup2 = field[ip[0].rm_eo];
   field[ip[0].rm_eo] = '\0';

   /* Convert IP from string form to ip_addr_t */
   if (ip_from_str(field + ip[0].rm_so, &tmp_ip) != 1) {
      field[ip[0].rm_eo] = backup2;
      field[field_len] = backup;
      return output;
   }

   uint32_t *ip_v4_ptr, ip_v4_anon;
   uint64_t *ip_v6_ptr, ip_v6_anon[2] = {0};
   char anon_ip_string[INET6_ADDRSTRLEN + 1];

   memset(anon_ip_string, 0, INET6_ADDRSTRLEN + 1);

   /* Anonymize or deanonymize IP */
   if (ip_is4(&tmp_ip)) {
      ip_v4_ptr = (uint32_t *) ip_get_v4_as_bytes(&tmp_ip);
      if (mode == ANONYMIZATION) {
         ip_v4_anon = anonymize(ntohl(*ip_v4_ptr));
      } else {
         ip_v4_anon = deanonymize(ntohl(*ip_v4_ptr));
      }
      tmp_ip = ip_from_4_bytes_le((void *) &ip_v4_anon);
      ip_to_str(&tmp_ip, anon_ip_string);
   } else {
      ip_v6_ptr = (uint64_t *) &tmp_ip;
      if (mode == ANONYMIZATION) {
         anonymize_v6(ip_v6_ptr, ip_v6_anon);
      } else {
         deanonymize_v6(ip_v6_ptr, ip_v6_anon);
      }

      ip_to_str((ip_addr_t *)(void *) &ip_v6_anon, anon_ip_string);
   }

   /* Restore backup characters */
   field[ip[0].rm_eo] = backup2;
   field[field_len] = backup;

   /* Allocate space for anonymized string */
   size_t new_length = strlen(anon_ip_string);
   output = (char *) calloc(ip[0].rm_so + new_length + (field_len - ip[0].rm_eo) + 1 , sizeof(char));
   if (!output) {
      return output;
   }

   /* Copy string to allocated space */
   strncpy(output, field, ip[0].rm_so);
   strncpy(output + ip[0].rm_so, anon_ip_string, new_length);
   strncpy(output + ip[0].rm_so + new_length, field + ip[0].rm_eo, field_len - ip[0].rm_eo);

   return output;
}

/** \brief Anonymize fields of the UniRec record
 * Anonymize IP addresses in all fields in "anon_fields" array.
 * \param[in]     tmplt      Pointer to Unirec template.
 * \param[in-out] data       Pointer to Unirec flow record data.
 * \param[in]     mode       Anonymizer mode (ANONYMIZATION or DEANONYMIZATION).
 * \param[in]     fields_cnt Number of ids in "anon_fields" array.
 * \param[in]     regex_IPV4 Compiled regular expression to match IPv4.
 * \param[in]     regex_IPV6 Compiled regular expression to match IPv6.
 * \return        void
*/
void anon_present_fields(ur_template_t *tmplt, void *data, uint8_t mode, regex_t regex_IPV4, regex_t regex_IPV6)
{
   int i;

   for (i = 0; i < anon_fields_cnt; i++) {
      void *field_ptr = ur_get_ptr_by_id(tmplt, data, anon_fields[i]);
      uint32_t field_len = ur_get_len(tmplt, data, anon_fields[i]);

      if (ur_is_static(anon_fields[i]) > 0) {
         ip_anonymize(field_ptr, mode);
      } else {
         char *output = string_anonymize(field_ptr, field_len, mode, regex_IPV4, regex_IPV6);
         if (output) {
            ur_set_string(tmplt, data, anon_fields[i], output);
            free(output);
         }
      }
   }
}

/** \brief Check template for anonymizeable fields
 * Check template for anonymizeable fields and set up "anon_fields" array
 * \param[in] tmplt Pointer to Unirec template.
 * \return    int   Number of anonymizeable fields present in template.
*/
int set_fields_present(ur_template_t *tmplt)
{
   int i, j = 0;

   for (i = 0; i < ANON_FIELDS_COUNT; i++) {
      anon_fields[j] = ur_get_id_by_name(anon_field_names[i]);
      if (anon_fields[j] != UR_E_INVALID_NAME && ur_is_present(tmplt, anon_fields[j])) {
         j++;
      }
   }
   anon_fields_cnt = j;
   return j;
}

// NMCM_PROGRESS_DECL


int main(int argc, char **argv)
{
//    NMCM_PROGRESS_DEF
   int ret, reti, i;
   uint8_t init_key[32] = {0};
   char *secret_key = "01234567890123450123456789012345";
   char *secret_file = NULL;
   int first = 1;
   void *anon_rec = NULL;
   ur_template_t *tmplt = NULL;
   regex_t regex_IPV4, regex_IPV6;

   uint8_t mode = ANONYMIZATION;          // Default mode
   ANONYMIZATION_ALGORITHM = RIJNDAEL_BC; // Default algorithm

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   // Fill in the list of supported fields in module description
   {
      // create string with list of supported fields
      int fields_desc_len = 0;
      for (i = 0; i < ANON_FIELDS_COUNT; i++) {
         fields_desc_len += strlen(anon_field_names[i]) + 2; // +2 for delimiter (", ")
      }
      fields_desc_len -= 2; // last delimiter
      char *fields_desc = (char *) calloc(fields_desc_len + 1, sizeof(char));
      if (!fields_desc) {
          fprintf(stderr, "Error: Memory allocation problem (module description).\n");
          ret = 5;
          goto cleanup2;
      }
      for (i = 0; i < ANON_FIELDS_COUNT; i++) {
         if (i > 0) {
            strcat(fields_desc, ", ");
         }
         strcat(fields_desc, anon_field_names[i]);
      }
      // Fill the list into module's description
      free(module_info->description); // free old description that was allocated in INIT_MODULE_INFO_STRUCT
      module_info->description = malloc(strlen(MODULE_DESCRIPTION_TEMPLATE) + fields_desc_len);
      if (!module_info->description) {
          fprintf(stderr, "Error: Memory allocation problem (module description).\n");
          ret = 5;
          goto cleanup2;
      }
      sprintf(module_info->description, MODULE_DESCRIPTION_TEMPLATE, fields_desc);
      free(fields_desc);
   }
      

   // ***** TRAP initialization *****
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   //signal(SIGUSR1, signal_handler); //signal not used in previous commit

   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'k':
         secret_key = optarg;
         break;
      case 'f':
         secret_file = optarg;
         break;
      case 'M':
         ANONYMIZATION_ALGORITHM = MURMUR_HASH3;
         break;
      case 'd':
         mode = DEANONYMIZATION;
         break;
      default:
         fprintf(stderr, "Invalid arguments.\n");
         ret = 1;
         goto cleanup;
      }
   }

   // Check if secret key was specified and initialize panonymizer
   if (secret_file != NULL) {
      if (!init_from_file(secret_file, init_key)) {
         ret = 2;
         goto cleanup;
      }
   } else {
      if (!ParseCryptoPAnKey(secret_key, init_key)) {
         ret = 3;
         goto cleanup;
      }
      PAnonymizer_Init(init_key);
   }
   // ***** Create UniRec input template *****

   tmplt = ur_create_input_template(0, NULL, NULL);
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, NULL);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Unable to create input template.\n");
      ret = 4;
      goto cleanup;
   }

   anon_rec = calloc(UR_MAX_SIZE, 1);
   if (!anon_rec) {
      fprintf(stderr, "Error: Memory allocation problem (output alert record).\n");
      ret = 5;
      goto cleanup;
   }

   reti = regcomp(&regex_IPV4, IPV4_REGEX, REG_EXTENDED);
   if (reti) {
      ret = 6;
      goto cleanup;
   }

   reti = regcomp(&regex_IPV6, IPV6_REGEX, REG_EXTENDED);
   if (reti) {
      ret = 7;
      regfree(&regex_IPV4);
      goto cleanup;
   }

   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = TRAP_RECEIVE(0, data, data_size, tmplt);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         // Get the data format of senders output interface (the data format of the output interface it is connected to)
         const char *spec = NULL;
         uint8_t data_fmt = TRAP_FMT_UNKNOWN;
         if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Data format was not loaded.");
            break;
         }
         // Set the same data format to the output interface
         trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec);
         if (set_fields_present(tmplt) < 1) {
            fprintf(stderr, "Warning: No fields for anonymizing present in input template.");
         }
      } else {
         TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
      }
      if (data_size <= 1) {
         printf("EOF received\n");
         break; // End of data (used for testing purposes)
      }

      memcpy(anon_rec, data, data_size);
      anon_present_fields(tmplt, anon_rec, mode, regex_IPV4, regex_IPV6);

      // Send anonymized data
      if (first == 1) {
         //set output format for first output record.
         ur_set_output_template(0,tmplt);
         first = 0;
      }
      trap_send(0, anon_rec, ur_rec_size(tmplt, anon_rec));
   }

   regfree(&regex_IPV4);
   regfree(&regex_IPV6);
   ret = 0;
cleanup:
   // ***** Do all necessary cleanup before exiting *****

   TRAP_DEFAULT_FINALIZATION();
   if (tmplt) {
      ur_free_template(tmplt);
   }

   if (anon_rec) {
      free(anon_rec);
   }

   ur_finalize();

cleanup2:
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return ret;
}
