/**
 * \file blooming_history_functions.h
 * \brief History of communicating entities using bloom filters.
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2013,2014,2015,2016,2017,2018 CESNET
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

#ifndef __BLOOMING_HISTORY_FUNCTIONS_H_
#define __BLOOMING_HISTORY_FUNCTIONS_H_

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

#endif // __BLOOMING_HISTORY_FUNCTIONS_H_
