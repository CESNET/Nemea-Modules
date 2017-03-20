/**
 * \file topn.h
 * \brief Topn module for computing various Top N statistics online.
 * \author Dominik Tran <xtrand00@stud.fit.vutbr.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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

#ifndef _TOPN_
#define _TOPN_

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <nemea-common.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include <string.h>
#include <time.h>

#include "twister.h" //!< Pseudorandom number generator

#define HASH_TABLE_SIZE 8192 
#define FLOWS_TIME_INTERVAL 16  
#define FLOWS_MULTIPLIER 8  
#define FLOWS_BIG_BASE 800  
#define FLOWS_BIG_MULTIPLIER 600 
#define FLOWS_RANDOM_MAX 256
#define FLOWS_RANDOM 16
#define PAB_TIME_INTERVAL 8
#define PAB_BASE 8
#define PAB_MULTIPLIER 3

typedef struct flow_struct {
   uint32_t max_number;     /*!< max_number represents bytes or packets. flow_t is used for flows with both packets and bytes, having single variable allows for single function that can process both packets and bytes */ 
   ip_addr_t src_ip; 
   ip_addr_t dst_ip;
   uint16_t src_port;
   uint16_t dst_port;
   uint8_t protocol;
} flow_t;

typedef struct port_struct {
   uint64_t packets;
   uint64_t bytes;
   uint16_t port;     		/*!< Stats about ports are saved in big array of 65 536 ports, number of port is used as index (and so index = port number). When stats are about to be printed, qsort is used to get Topn ports - this however messes up indexes - thus additional info about port number needs to be saved */ 
   uint64_t flows; 
} port_t;

typedef struct ip_struct {
   uint64_t flows;
   uint64_t bytes;
   uint64_t packets;  
   ip_addr_t src_ip;   /*!< Hash table is used for saving stats about IPs and networks. Similar to port_t, qsort is used and since data and key(=IP) fields in hash table are in a different memory space, info about IP needs to be saved. */  
} ip_t;

/**
* \brief Function sets variable which results in printing Topn stats.
*/
void sig_handler(int signal);

/**
* \brief Function returns index where new flow record should be placed.
*
* This function is used to find out whether the new flow is bigger than any other flow record in a given sorted array. It uses binary search to find first smaller flow. If no smaller flow is found, -1 is returned. If smaller flow is found, then it returns index of that smaller flow.
*
* \param key Basically number of packets/bytes of new flow record.
* \param sorted_array Sorted array of pointers pointing to elements of array of flow_t records.
* \param num Number of elements in a given sorted array.
* \return -1 if no smaller flow found, index of first smaller flow otherwise.
*/
int get_array_index(uint32_t key, flow_t ** sorted_array, size_t num);

/**
* \brief Function processes flows for top N flows stats - adds new big flow, removes smallest one.
*
* Stats about Topn flows are stored in an array of TOP_N elements of flow_t type. Having only TOP_N elements (lower memory consumption) means once full, only biggest new flows can be added and for each new flow added, smallest one in array will get removed. If Topn is 1000, linear loop through array would be slow thus binary search is used instead. Binary search means array have to sorted. If new biggest flow is added, all current elements have to be moved by 1. To avoid moving too much memory, I use array of pointers which is sorted, each pointer points to (indexes to) flow_t element in unsorted array of flow_t records.
*
* Function uses get_array_index function to find out if given flow is big enough to be added to array of topn flows. If array isn't full, it's added regardless. If array is full and it's big enough, it's added. During any add of new member, sorted array is moved accordingly.
*
* \param array Array of flow records.
* \param sorted_array Sorted array of pointers pointing to elements of array of flow_t records.
* \param record Record containing info about given flow.
* \param array_counter Number of how many members array currently contains.
*/
void process_flows(flow_t * array, flow_t ** sorted_array, flow_t* record, int array_counter);

/**
* \brief Function prints top N flows.
*
* \param sorted_array_of_bytes Sorted array of pointers pointing to array that contains flows with top N bytes.
* \param sorted_array_of_packets Sorted array of pointers pointing to array that contains flows with top N packets.
* \param array_counter Number of elements in both sorted arrays.
* \param ip_string Pointer for ip_to_str function.
* \param ip_string2 Pointer for ip_to_str function.
* \param port_number Changes text output slightly.
*/
void print_top_flows(flow_t ** sorted_array_of_bytes, flow_t ** sorted_array_of_packets, int array_counter, char * ip_string, char *ip_string2, int port_number);

/**
* \brief Function prints top N ports.
*
* \param array_of_ports Array containing stats of all ports.
* \param port_number Changes text output slightly.
*/
void print_top_ports(port_t * array_of_ports, int port_number);

/**
* \brief Function prints top N ports.
*
* \param ip_string Pointer for ip_to_str function.
* \param table_pab Pointer to the hash table containing IPs with most packets and bytes.
* \param fhf_iter_t Pointer to the iterator of table_pab.
* \param table_flows Pointer to the hash table containing IPs with most flows.
* \param fht_iter_t Pointer to the iterator of table_flows.
* \param port_number Changes text output slightly.
* \param prefix_set Changes text output slightly.
*/
void print_top_ip(char * ip_string, fhf_table_t * table_pab, fhf_iter_t * iter_pab, fht_table_t * table_flows, fht_iter_t * iter_flows,int port_number, int prefix_set);

/**
* \brief Function processes arguments for -m parameter (length of the prefixes).
*
* \param optarg String containing arguments.
* \param prefix128 Array of 2 elements of uint64_t type, together they make 128 bits, function will convert IPv6 length (eg 4) to appropriate mask (eg 0...01111) and fill prefix128 with this mask.
* \param prefix Same as prefix128 except for IPv4. 
* \param prefix_set Pointer to variable which will be set according to given arguments.
* \param prefix_only_v4 Pointer to variable which will be set according to given arguments.
* \return 0 if OK, -1 if error occurred.
*/
int process_prefix_args(char * optarg, uint64_t *prefix128, uint32_t * prefix, int * prefix_set, int * prefix_only_v4);

/**
* \brief Function processes arguments for -p parameter (various number of ports).
*
* Function allocates memory for global variable int * port and fills each element with port numbers given in an optarg parameter.
*
* \param optarg String containing arguments.
* \return 0 if OK, -1 if error occurred.
*/
int process_ports_args(char * optarg);

/**
* \brief Function processes incoming flows and manages hash table of top N IPs with most flows.
*
* Function uses fast_hash_table from Nemea-Framework/common/, which is a fast 4-way hash table with least recently used (LRU) algorithm used to replace oldest record in a row. This is useful because we can expect that most active IPs will be able to keep themselves in a table.
*
* When the new flow is received, function checks if it's key (IP) is already in table. If yes, it's updated (+1 flow). If not, it's added to the table, possibly replacing oldest record if a given row is full. Because real network contains a lot of flows per second and this module aims to not use too much memory, some improvements have been made - based on observation that most network traffic is small and probably won't make it to top N. First is that it uses probability sampling - so that only e.g. 1 in 10 flows will be processed. Second is that if a row is full, each member is inspected and if it's number of flow is lower than computed number that scales with time, it's removed. Computed number should be small enough to not remove any big/huge records. So IPs with small potential to appear in top N and passed probability test will be removed and row won't be full. Third improvement is that if a record is replaced by a new one and during second improvement some elements have been removed, then number of flows of replaced record is inspected. If it's bigger than computed number (which should be rather big/huge), it's returned to hash table. This is made for cases where IP with big chance to appear in top N is removed because at some time a lot of new IPs are added to the same row, despite none of them probably make it to top N.
*
* \param table_flows Pointer to hash table, where records will be stored.
* \param ip IP address, will be used as key to hash table.
* \param record Record containing data which will be saved to hash table.
* \param key_lost If new record removes least recentl  used one, removed key will go there.
* \param data_lost If new record removes least recently used one, removed data will go there.
* \param data Used for UniRec functions and macros.
* \param tmplt Used for UniRec functions and macros.
*/
void process_ip_flows(fht_table_t * table_flows, ip_addr_t * ip, ip_t * record, ip_addr_t * key_lost, ip_t * data_lost, const void *data, ur_template_t *tmplt);

/**
* \brief Function processes incoming flows and manages hash table of top N IPs with most packets and bytes.
*
* Function is somewhat similar to function process_ip_flows, but uses fast_hash_filter from Nemea-Framework/common/, which is a fast 8-way hash table with no replacement algorithm. Unlike processing IPs with top N flows where flows come only by 1 (+1) and thus it's difficult to predict which IP will make it to top N, processing IPs with most packets and bytes is simpler. Based on observation, biggest flow (from top N flows with most bytes stats) can be 100 000x bigger than average of all received bytes in a given time. Also usually more packets = more bytes, so I use only 1 hash table to save memory. 
*
* When the new flow is received, function checks if it's key (IP) is already in table. If yes, it's updated. If not, it's added to the table, if row isn't full. If row is full, each member is inspected and if it's number of packets and bytes is lower than computed number, it's removed. Computed number is based of average of received packets and bytes and scales with time. It should be small enough to not remove any big/huge records. If any records were removed, new flow is added if it's packets or bytes are bigger than some small multiplier of average.
*
* \param table_pab Pointer to hash table, where records will be stored.
* \param ip IP address, will be used as key to hash table.
* \param record Record containing data which will be saved to hash table.
* \param data Used for UniRec functions and macros.
* \param tmplt Used for UniRec functions and macros.
* \param average_packets Arithmetic mean of all received packets in a given time.
* \param average_bytes Arithmetic mean of all received bytes in a given time.
*/
void process_ip_pab(fhf_table_t * table_pab, ip_addr_t * ip, ip_t * record, const void *data, ur_template_t *tmplt, int average_packets, int average_bytes);

/**
* \brief Function writes message to stderr and exits program.
*/
void malloc_err(void);

/**
* \brief Function used by library function qsort().
*/
int compare_flows(const void * a, const void * b);

/**
* \brief Function used by library function qsort().
*/
int compare_packets(const void * a, const void * b);

/**
* \brief Function used by library function qsort().
*/
int compare_bytes(const void * a, const void * b);

/**
* \brief Function used by library function qsort().
*/
int compare_flows_table(const void * a, const void * b);

/**
* \brief Function used by library function qsort().
*/
int compare_packets_table(const void * a, const void * b);

/**
* \brief Function used by library function qsort().
*/
int compare_bytes_table(const void * a, const void * b);

#endif /* _TOPN_ */

