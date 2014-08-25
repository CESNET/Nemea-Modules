/**
 * \file anonymizer.c
 * \brief Module for anonymizing incoming flow records. 
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
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



#define IP_V6_SIZE 16           // 128b or 16B is size of IP address version 6
#define SECRET_KEY_FILE "secret_key.txt"   // File with secret key
#define SECRET_KEY_MAX_SIZE 67             // Max length of secret key


/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Anonymizer", // Module name
   // Module description
   "Module for anonymizing incoming flow records.\n"
   "Parameters:\n"
   "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
   "   -k KEY      Specify secret key*.\n"
   "   -f FILE     Specify file containing secret key*.\n" 
   "   -M          Use MurmurHash3 instead of Rijndael cipher."
   "Interfaces:\n"
   "   Inputs: 1\n"
   "   Outputs: 1\n"
   "*Secret key must be 32 characters long string or 32B sized hex string starting with 0x\n",
   1, // Number of input interfaces
   1, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER();

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
 * \param[in] tmplt Pointer to Unirec template.
 * \param[in-out] data Pointer to Unirec flow record data.
 * \return void.
*/
void ip_anonymize(ur_template_t *tmplt, const void *data)
{
   uint32_t  ip_v4_anon;
   uint32_t *ip_v4_ptr;
   uint64_t  ip_v6_anon[2];
   uint64_t *ip_v6_ptr;

   if (ip_is4(ur_get_ptr(tmplt, data, UR_SRC_IP))) {
      // Anonymize SRC IP version 4
      ip_v4_ptr =  (uint32_t *) ip_get_v4_as_bytes(ur_get_ptr(tmplt, data, UR_SRC_IP));
      ip_v4_anon = anonymize(ntohl(*ip_v4_ptr));
      *ip_v4_ptr = htonl(ip_v4_anon);

      // Anonymize DST IP version 4
      ip_v4_ptr = (uint32_t *) ip_get_v4_as_bytes(ur_get_ptr(tmplt, data, UR_DST_IP));
      ip_v4_anon = anonymize(ntohl(*ip_v4_ptr));
      *ip_v4_ptr = htonl(ip_v4_anon);
   } else {
      // Anonymize SRC IP version 6
      ip_v6_ptr = (uint64_t *) ur_get_ptr(tmplt, data, UR_SRC_IP);
      anonymize_v6(ip_v6_ptr, ip_v6_anon);
      memcpy(ip_v6_ptr, ip_v6_anon, IP_V6_SIZE);

      // Anonymize DST IP version 6
      ip_v6_ptr = (uint64_t *) ur_get_ptr(tmplt, data, UR_DST_IP);
      anonymize_v6(ip_v6_ptr, ip_v6_anon);
      memcpy(ip_v6_ptr, ip_v6_anon, IP_V6_SIZE);
   }


}




int main(int argc, char **argv)
{
   int ret;
   uint8_t init_key[32] = {0};
   char *secret_key = "01234567890123450123456789012345";
   char *secret_file = NULL;

   ANONYMIZATION_ALGORITHM = RIJNDAEL_BC; // Default algorithm

   // ***** ONLY FOR DEBUGING ***** //
   #ifdef DEBUG
      char ip1_buff[100] = {0};
      char ip2_buff[100] = {0};
   #endif
   // ***************************** //



   // ***** TRAP initialization *****   
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   //signal(SIGUSR1, signal_handler); //signal not used in previous commit
   


   // ***** Create UniRec template *****   
   char *unirec_specifier = "<COLLECTOR_FLOW>";
   char opt;
   while ((opt = getopt(argc, argv, "u:k:f:M")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
            break;
         case 'k':
            secret_key = optarg;
            break;
         case 'f':
            secret_file = optarg;
            break;
         case 'M':
            ANONYMIZATION_ALGORITHM = MURMUR_HASH3;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 3;
      }
   }
   
   ur_template_t *tmplt = ur_create_template(unirec_specifier);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      return 4;
   }


   // Check if secret key was specified and initialize panonymizer
   if (secret_file != NULL) {
      if (!init_from_file(secret_file, init_key)) {
         trap_finalize();
         return 7;
      }
   } 
   else {
      if (!ParseCryptoPAnKey(secret_key, init_key)) {
         trap_finalize();
         return 7;
      }
      PAnonymizer_Init(init_key);
   }

  
   
   
   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
      
      // Check size of received data
      if (data_size < ur_rec_static_size(tmplt)) {
         if (data_size <= 1) {
            break; // End of data (used for testing purposes)
         }
         else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(tmplt), data_size);
            break;
         }
      }
      
     
   
      // ***** ONLY FOR DEBUGING ***** //
      #ifdef DEBUG
         ip_to_str(ur_get_ptr(tmplt, data, UR_SRC_IP), ip1_buff);
         ip_to_str(ur_get_ptr(tmplt, data, UR_DST_IP), ip2_buff);
         printf("ORIG: %15s   ->   %15s\n", ip1_buff, ip2_buff);           
         ip_anonymize(tmplt, data);
         ip_to_str(ur_get_ptr(tmplt, data, UR_SRC_IP), ip1_buff);
         ip_to_str(ur_get_ptr(tmplt, data, UR_DST_IP), ip2_buff);
         printf("ANON: %15s   ->   %15s\n\n", ip1_buff, ip2_buff);
      #endif
      // ***************************** //

      #ifndef DEBUG
         ip_anonymize(tmplt, data);
      #endif

      // Send anonymized data
      trap_send_data(0, data, ur_rec_size(tmplt, data), TRAP_NO_WAIT); 


   }
  
  // ***** ONLY FOR DEBUGING ***** //
  #ifdef DEBUG
     char dummy[1] = {0};
     trap_send_data(0, dummy, 1, TRAP_WAIT); 
  #endif   
  // ***************************** //

   // ***** Do all necessary cleanup before exiting *****
   TRAP_DEFAULT_FINALIZATION();
   ur_free_template(tmplt);

   return 0;
}

