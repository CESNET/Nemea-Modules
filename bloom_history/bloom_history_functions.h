/**
 * \file bloom_history_functions.h
 * \brief History of communicating entities using bloom filters.
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */

#ifndef __BLOOM_HISTORY_FUNCTIONS_H_
#define __BLOOM_HISTORY_FUNCTIONS_H_
#define _GNU_SOURCE

#include <stdint.h>

#include <curl/curl.h>
#include <unirec/unirec.h>

#include "bloom.h"


/**
 * Test that ip is from given network prefix.
 *
 * \param[in] ip                        IP address that is checked for membership in the given prefix.
 * \param[in] protected_prefix          IP prefix.
 * \param[in] protected_prefix_length   Length of the IP prefix.
 * \returns 1 if the ip is from prefix, 0 otherwise.
*/
int is_from_prefix(ip_addr_t *ip, ip_addr_t *protected_prefix, int32_t protected_prefix_length);


/**
 * Initialize libcurl easy handle.
 *
 * libcurl does reuse connections on the same heasy handle so it is preferable
 * to do the initialization only once.
 *
 * \param[in] curl                  Libcurl easy handle.
 * \param[out] aggregator_service   URI of the Aggregator service.
 * \returns
 *      0 - success
 *     -1 - initialization failed
*/
int curl_init_handle(CURL **curl);


/**
 * Serialize and send bloom filter struct to a aggregator service via HTTP POST.
 *
 * \param[in] curl                      Libcurl easy handle.
 * \param[in] aggregator_service_url    Aggregator service upload uri.
 * \param[in] bloom_filter              Bloom filter to be sent.
 * \returns
 *      0 - success
 *     -1 - bloom filter not initialized
 *     -2 - serialization failed
 *     -3 - curl handle not initialized
 *     -4 - libcurl error
 *     -5 - HTTP status code other than 200 OK
*/
int curl_send_bloom(CURL *curl, const char *aggregator_service_url, const struct bloom *bloom_filter);


/**
 * Free libcurl easy handle.
 *
 * \param[in] curl   Libcurl easy handle.
*/
void curl_free_handle(CURL **curl);


void *pthread_entry_upload(void *idx);


#endif // __BLOOM_HISTORY_FUNCTIONS_H_
