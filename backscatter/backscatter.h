/**
 * \file backscatter.h
 * \brief Constants, structures and functions specific for backscatter.cpp
 * \author Martin Marusiak <xmarus07@stud.fit.vutbr.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#ifndef BACKSCATTER_H
#define BACKSCATTER_H

#include "backscatter_common.h"
#include "EventTracker.h"

/**
 * Only flows time window [A-NEGATIVE, A+POSITIVE] where A is current time will processed
 */
#define TIME_WINDOW_NEGATIVE 60
/**
 * Only flows time window [A-NEGATIVE, A+POSITIVE] where A is current time will processed
 */
#define TIME_WINDOW_POSITIVE 30
/**
 * Default active timeout value
 */
#define ACTIVE_TIMEOUT 7200
/**
 * Default passive timeout value
 */
#define PASSIVE_TIMEOUT 150
/**
 * Default expected flow per second rate
 */
#define FPS 400000
/**
 * Default connection history size, 20 million stores approximately 5 minutes
 */
#define CONNECTION_HISTORY_SIZE 120
/**
 * Default false positive rate for connection history
 */
#define CONNECTION_FP_RATE 0.05
/**
 * Default feature history size in seconds (used for unique src/dst port + dst ip features)
 */
#define FEATURE_HISTORY_SIZE 1800
/**
 * Default feature history rate (expected rate of backscatter like packets)
 */
#define FEATURE_FPS 10000
/**
 * Number of features using feature history
 */
#define HISTORY_FEATURES 4
/**
 * Default false positive rate for feature history
 */
#define FEATURE_FP_RATE 0.01
/**
 * Default export threshold (feature vector must consist of least this number of flows to be exported) *
 */
#define EXPORT_THRESH 30

/**
 * Module parameters
 */
struct parameters {
    uint32_t active_timeout;
    uint32_t passive_timeout;
    uint32_t c_fps;
    uint32_t c_history_size;
    float c_history_fp;
    uint32_t f_fps;
    uint32_t f_history_size;
    float f_history_fp;
    uint32_t bs_buffer_size;
    uint32_t threshold;
    uint32_t time_window_negative;
    uint32_t time_window_positive;
    uint32_t out;
    bool print;
};
/**
 * Module statistics
 */
struct statistics {
    size_t total_flows = 0;
    size_t bs_like_flows_tcp = 0;
    size_t bs_like_flows_icmp = 0;
    size_t bs_like_flows_oneway_tcp = 0;
    size_t bs_like_flows_oneway_icmp = 0;
    size_t full_bs_buffer = 0;
    size_t skipped_flows = 0;
    size_t time_resets = 0;
    size_t ipv6 = 0;
};

/**
 * Process buffer record - single flow
 * @param history Connection history
 * @param buffer Backscatter buffer
 * @param etracker Event tracker
 * @param counter Counter tracking number of backscatter like oneway flows
 */
void inline process_buffer_record(TemporaryHistory &history, std::priority_queue<record, std::vector<record>> &buffer,
                                  EventTracker &etracker, statistics &stats){

    record rec = buffer.top();
    uint32_t connection[2] = {rec.dst_ip, rec.src_ip};
    if(rec.proto == TCP){
        stats.bs_like_flows_tcp++;
    } else if(rec.proto == ICMP) {
        stats.bs_like_flows_icmp++;
    }

    if(!history.contains((const unsigned char *) connection, sizeof(connection))) {
        if(rec.proto == TCP){
            stats.bs_like_flows_oneway_tcp++;
        } else if(rec.proto == ICMP) {
            stats.bs_like_flows_oneway_icmp++;
        }
        etracker.add(rec);
    }
    buffer.pop();
}

/**
 * Check if flow has backscatter like flags/ICMP type
 * @param proto Flow protocol
 * @param flags Flow fags
 * @return True if flow has typical backscatter flags/ICMP type
 */
bool inline is_bs_like(uint8_t proto, uint8_t flags){
    if(proto == TCP){
        if(flags == ACKSYN || flags == RST){
            return true;
        }
    } else if (proto == ICMP){
        if(flags == ECHO_REPLY || flags == DEST_UNREACHABLE ||
           flags == TIME_EXCEEDED || flags == SOURCE_QUENCH || flags == REDIRECT ||
           flags == PARAMETER_PROBLEM || flags == TIMESTAMP_REPLY ||
           flags == INFORMATION_REPLY || flags == ADDRESS_MASK_REPLY){
            return true;
        }
    }
    return false;
}

#endif //BACKSCATTER_H
