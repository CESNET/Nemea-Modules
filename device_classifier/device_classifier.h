/**
 * \file device_classifier.h
 * \brief Module for labeling devices according to their network traffic.
 * \author Zdenek Kasner <kasnezde@fit.cvut.cz>
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

#ifndef _DEVICE_CLASSIFIER_
#define _DEVICE_CLASSIFIER_

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
#include <stdbool.h>
#include <float.h>
#include <math.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "b_plus_tree.h"
#include "libsvm/svm.h"
#include "fields.h"

#define IP_VERSION_4_BYTES 4 /**< Size of IP address in bytes */
#define PAUSE_THRESHOLD (60*1000) /**< Pause after which the communication is considered as a new biflow  */
#define USAGE_THRESHOLD 0.01 /**< Ratio of port usage to be included in feature vector */
#define BASIC_STATS_CNT 11 /**< Number of basic statistical features */
#define PORT_CNT 49152 /**< Number of distinguished ports (above aggregated as one) */
#define FEATURE_CNT (BASIC_STATS_CNT+PORT_CNT) /**< Total number of features */
#define MAX_MODELS 1024 /**< Maximal number of models */
#define MAX_RESERVED_SUBNETS 32 /**< Maximal size of a list with reserved IP addresses */

/**
 * SVM model for classifying a label
 */
typedef struct model_t {
    char *name; /**< Output label name */
    int id; /**< Label ID in training data */
    struct svm_model *model; /**< SVM model */
} model_t;

/**
 * Node of a linked list with ports
 */
typedef struct port_t {
    uint16_t port; /**< Port number */
    uint64_t total; /**< Port usage */
    struct port_t *next; /**< Pointer to the next node in linked list */
} port_t;

/**
 * Node of a B+ tree with statistical values of an IP address.
 */
typedef struct node_t {
    void *peer_tree; /**< B+ tree with peers */
    uint64_t peers; /**< Number of peers */
    uint64_t total_biflows; /**< Number of biflows */
    uint64_t total_inits; /**< Number of initialized biflows */
    uint64_t flows_src; /**< Number of source flows */
    uint64_t flows_dst; /**< Number of destination flows */
    port_t *port_head; /**< Head of the linked list with port */
    uint16_t port_cnt; /**< Number of used ports */
    uint64_t tcp_cnt; /**< TCP protocol usage */

    uint64_t bytes_src; /**< Number of source bytes */
    uint64_t bytes_src_2; /**< Number of source bytes squared */
    uint64_t bytes_dst; /**< Number of destination bytes */
    uint64_t bytes_dst_2; /**< Number of destination bytes squared */
    uint64_t packets_src; /**< Number of source packets */
    uint64_t packets_src_2; /**< Number of source packets squared */
    uint64_t packets_dst; /**< Number of destination packets */
    uint64_t packets_dst_2; /**< Number of destination packets squared */
    uint64_t time_src_msec; /**< Length of source flows */
    uint64_t time_src_msec_2; /**< Length of source flows squared */
    uint64_t time_dst_msec; /**< Length of destination flows */
    uint64_t time_dst_msec_2; /**< Length of destination flows squared */
 
    struct svm_node *features; /**< Feature vector */
    bool labels[MAX_MODELS]; /**< Predicted labels */
} node_t;

/**
 * Rule for filtering or training.
 */
typedef struct ip_rule_t {
    ip_addr_t ip_addr; /**< IP address */
    int subnet; /**< Subnet mask */
    bool labels[MAX_MODELS]; /**< Training labels (ground-truth) */
    int label_cnt; /**< Number of training labels */
    char *label_name; /**< Reserved IP address label */
} ip_rule_t;

/**
 * Node of a B+ tree for a peer IP address of a tracked IP adress.
 */
typedef struct peer_t {
    ip_addr_t peer_ip; /**< IP address */
    uint64_t time_last; /**< TIME_LAST of the last mutual flow */
} peer_t;

/**
 * Structure to hold information about a flow
 */
typedef struct flow_t {
    uint32_t packets; /**< Number of packets in the flow */
    uint64_t bytes; /**< Number of bytes in the flow */
    uint16_t src_port; /**< Source port of the flow */
    uint16_t dst_port; /**< Destination port of the flow */
    uint8_t  protocol; /**< Protocol of the flow */
    uint64_t time_first; /**< Beginning of the flow */
    uint64_t time_last; /**< End of the flow */
} flow_t;

#define train_script BINDIR "/svm-tools"
#define models_dir "/data/device_classifier/"
#define train_db_fname "db.svm"
#define models_lst_fname "models.list"

#endif /* _DEVICE_CLASSIFIER_ */
