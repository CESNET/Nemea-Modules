/**
 * \file anonymizer.c
 * \brief Module for anonymizing incoming flow records.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \author Zdenek Rosa <rosazden@fit.cvut.cz>
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \author Martin Zadnik <zadnik@cesnet.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2013
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2013-2015 CESNET
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



#define IP_V6_SIZE 16           // 128b or 16B is size of IP address version 6
#define SECRET_KEY_FILE "secret_key.txt"   // File with secret key
#define SECRET_KEY_MAX_SIZE 67             // Max length of secret key

UR_FIELDS(
  ipaddr SRC_IP,      //Source address of a flow
  ipaddr DST_IP,      //Destination address of a flow
)

// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("anonymizer","Module for anonymizing incoming flow records.",1,1)

#define MODULE_PARAMS(PARAM) \
   PARAM('k', "key", "Specify secret key, the key must be 32 characters long string or 32B sized hex string starting with 0x", required_argument, "string") \
   PARAM('f', "file", "Specify file containing secret key, the key must be 32 characters long string or 32B sized hex string starting with 0x", required_argument, "string") \
   PARAM('M', "murmur", "Use MurmurHash3 instead of Rijndael cipher.", no_argument, "none") \
   PARAM('d', "de-anonym", "Switch to de-anonymization mode.", no_argument, "none")

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

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
    uint64_t * k_ptr = (uint64_t *) key;
    uint64_t k;
    uint32_t rep = key_size / 8;
    uint32_t i;

    for (i = 0; i < rep; i++)
    {
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
   fgets(secret_key, SECRET_KEY_MAX_SIZE, fp);
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



/** \brief Anonymize IP
 * Anonymize source and destination IP in Unirec using Crypto-PAn libraries
 * \param[in]     tmplt Pointer to Unirec template.
 * \param[in-out] data  Pointer to Unirec flow record data.
 * \param[in]     mode  Anonymizer mode (ANONYMIZATION or DEANONYMIZATION).
 * \return void.
*/
void ip_anonymize(ur_template_t *tmplt, const void *data, uint8_t mode)
{
   uint32_t  ip_v4_src_anon, ip_v4_dst_anon;
   uint32_t *ip_v4_src_ptr, *ip_v4_dst_ptr;
   uint64_t  ip_v6_src_anon[2] = {0}, ip_v6_dst_anon[2] = {0};
   uint64_t *ip_v6_src_ptr, *ip_v6_dst_ptr;

   if (ip_is4(ur_get_ptr(tmplt, data, F_SRC_IP))) {
      // Anonymize IP version 4
      ip_v4_src_ptr =  (uint32_t *) ip_get_v4_as_bytes(ur_get_ptr(tmplt, data, F_SRC_IP));
      ip_v4_dst_ptr =  (uint32_t *) ip_get_v4_as_bytes(ur_get_ptr(tmplt, data, F_DST_IP));
      if (mode == ANONYMIZATION) {
         ip_v4_src_anon = anonymize(ntohl(*ip_v4_src_ptr));
         ip_v4_dst_anon = anonymize(ntohl(*ip_v4_dst_ptr));
      } else {
         ip_v4_src_anon = deanonymize(ntohl(*ip_v4_src_ptr));
         ip_v4_dst_anon = deanonymize(ntohl(*ip_v4_dst_ptr));
      }
      *ip_v4_src_ptr = htonl(ip_v4_src_anon);
      *ip_v4_dst_ptr = htonl(ip_v4_dst_anon);
   } else {
      // Anonymize IP version 6
      ip_v6_src_ptr = (uint64_t *) ur_get_ptr(tmplt, data, F_SRC_IP);
      ip_v6_dst_ptr = (uint64_t *) ur_get_ptr(tmplt, data, F_DST_IP);
      if (mode == ANONYMIZATION) {
         anonymize_v6(ip_v6_src_ptr, ip_v6_src_anon);
         anonymize_v6(ip_v6_dst_ptr, ip_v6_dst_anon);
      } else {
         // Deanonymization of IPv6
         deanonymize_v6(ip_v6_src_ptr, ip_v6_src_anon);
         deanonymize_v6(ip_v6_dst_ptr, ip_v6_dst_anon);
      }
      memcpy(ip_v6_src_ptr, ip_v6_src_anon, IP_V6_SIZE);
      memcpy(ip_v6_dst_ptr, ip_v6_dst_anon, IP_V6_SIZE);
   }
}

// NMCM_PROGRESS_DECL


int main(int argc, char **argv)
{
//    NMCM_PROGRESS_DEF
   int ret;
   uint8_t init_key[32] = {0};
   char *secret_key = "01234567890123450123456789012345";
   char *secret_file = NULL;

   uint8_t mode = ANONYMIZATION;          // Default mode
   ANONYMIZATION_ALGORITHM = RIJNDAEL_BC; // Default algorithm

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // ***** ONLY FOR DEBUGING ***** //
#ifdef DEBUG
   char ip1_buff[100] = {0};
   char ip2_buff[100] = {0};
#endif
   // ***************************** //

//    NMCM_PROGRESS_INIT(10000,puts("-"))

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
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 3;
      }
   }

   // Check if secret key was specified and initialize panonymizer
   if (secret_file != NULL) {
      if (!init_from_file(secret_file, init_key)) {
         trap_finalize();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 7;
      }
   }
   else {
      if (!ParseCryptoPAnKey(secret_key, init_key)) {
         trap_finalize();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 7;
      }
      PAnonymizer_Init(init_key);
   }

   // ***** Create UniRec input template *****
   char *unirec_specifier = "SRC_IP,DST_IP";
   char *errstr = NULL;
   ur_template_t *tmplt = ur_create_input_template(0, unirec_specifier, &errstr);
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, "ipaddr SRC_IP,ipaddr DST_IP");

   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      if(errstr != NULL){
        fprintf(stderr, "%s\n", errstr);
        free(errstr);
      }
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 4;
   }

   int first = 1;
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
         // Set the same data format to repeaters output interface
         trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec);
      } else {
         TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
      }
      if (data_size <= 1) {
         printf("EOF received\n");
         break; // End of data (used for testing purposes)
      }
      if (data_size < ur_rec_fixlen_size(tmplt) || data_size > 250) {
#ifdef __cplusplus
         extern "C" {
#endif
            extern void *trap_glob_ctx;
#ifdef __cplusplus
         }
#endif
          extern void *trap_glob_ctx;
          printf("tmpl: %d\n", ur_rec_fixlen_size(tmplt));
          trap_ctx_create_ifc_dump(trap_glob_ctx, NULL);
          printf("%u\n", data_size);
          for (int i = -64; i < 256; i++) {
             printf("%02x ", (unsigned int)((unsigned char*)data)[i]);
             if (i % 16 == 15 || i % 16 == -1) {
                printf("\n");
             }
             if (i == -1) {
                printf("\n--\n");
             }
          }
          printf("\n");
          exit(1);
          fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                  ur_rec_fixlen_size(tmplt), data_size);
         continue;
      }


      // ***** ONLY FOR DEBUGING ***** //
#ifdef DEBUG
      char ip1_buff[64], ip2_buff[64];
      ip_to_str(ur_get_ptr(tmplt, data, F_SRC_IP), ip1_buff);
      ip_to_str(ur_get_ptr(tmplt, data, F_DST_IP), ip2_buff);
      fprintf(stderr, "ORIG: %15s   ->   %15s\n", ip1_buff, ip2_buff);
      ip_anonymize(tmplt, data, mode);
      ip_to_str(ur_get_ptr(tmplt, data, F_SRC_IP), ip1_buff);
      ip_to_str(ur_get_ptr(tmplt, data, F_DST_IP), ip2_buff);
      fprintf(stderr, "ANON: %15s   ->   %15s\n\n", ip1_buff, ip2_buff);
#endif
      // ***************************** //
#ifndef DEBUG
      ip_anonymize(tmplt, data, mode);
#endif

      // Send anonymized data
      if (first == 1) {
         //set output format for first output record.
         ur_set_output_template(0,tmplt);
         first = 0;
      }
      trap_send(0, data, data_size);
//       NMCM_PROGRESS_PRINT
   }

   // ***** ONLY FOR DEBUGING ***** //
#ifdef DEBUG
   char dummy[1] = {0};
   trap_send(0, dummy, 1);
#endif
   // ***************************** //

   // ***** Do all necessary cleanup before exiting *****
   TRAP_DEFAULT_FINALIZATION();
   ur_free_template(tmplt);
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return 0;
}

