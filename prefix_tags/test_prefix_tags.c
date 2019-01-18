/**
 * \file test_bloom_history.c
 * \brief History of communicating entities using bloom filters.
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2019
 */

#include <unirec/unirec.h>

#include "prefix_tags_functions.h"


void test_is_from_prefix(const char *ip_str, const char *prefix_str, int32_t prefix_length, int expected_result)
{
   ip_addr_t ip, prefix;

   printf("Testing: (%s, %s, %d, %d) ", ip_str, prefix_str, prefix_length, expected_result);

   ip_from_str(ip_str, &ip);
   ip_from_str(prefix_str, &prefix);

   if (is_from_prefix(&ip, &prefix, prefix_length) == expected_result) {
      printf("OK\n");
   } else {
      printf("FAIL\n");
   }
}


int main(int argc, char **argv)
{
   printf("========== TEST is_from_prefix ==========\n");
   // Mixing v4 and v6
   test_is_from_prefix("192.169.0.1", "FE08::", 64, 0);
   test_is_from_prefix("FE08::1", "192.169.0.0", 64, 0);
   // Mixing v4 and v6 - same binary prefix
   test_is_from_prefix("FE08::1", "254.1.0.0", 16, 0);
   test_is_from_prefix("254.1.0.1", "FE08::", 16, 0);
   // v4
   test_is_from_prefix("192.168.0.1", "192.168.0.0", 24, 1);
   test_is_from_prefix("192.168.1.1", "192.168.0.0", 24, 0);
   // v4 bits%8 test
   test_is_from_prefix("192.168.128.1", "192.168.128.0", 25, 1);
   test_is_from_prefix("192.168.128.1", "192.168.0.0", 25, 0);
   test_is_from_prefix("192.169.0.1", "192.169.0.0", 23, 1);
   test_is_from_prefix("192.169.0.1", "192.168.0.0", 23, 0);
   // v4 oddballs
   test_is_from_prefix("192.168.128.1", "192.168.128.1", 32, 1);
   test_is_from_prefix("192.168.128.2", "192.168.128.1", 32, 0);
   // v6
   test_is_from_prefix("FE08::1", "FE08::", 64, 1);
   test_is_from_prefix("FE08:BEEF::1", "FE08::", 64, 0);
   test_is_from_prefix("FE08::1", "FE08::", 16, 1);
   // v6 bits%8 test
   test_is_from_prefix("FE08:8000::1", "FE08:8000::", 17, 1);
   test_is_from_prefix("FE08:8000::1", "FE08::", 17, 0);
   test_is_from_prefix("FE09::1", "FE08::", 15, 1);
   test_is_from_prefix("FE0A::1", "FE08::", 15, 0);
   /* // v6 oddballs */
   test_is_from_prefix("FE08::1", "::", 0, 1);
   test_is_from_prefix("FE08::1", "FE08::1", 128, 1);
   test_is_from_prefix("FE08::2", "FE08::1", 128, 0);
   printf("========== END ==========\n");
   return 0;
}

