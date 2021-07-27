/**
 * \file FeatureVector.cpp
 * \brief Class for representing feature vector
 * \author Martin Marusiak<xmarus07@stud.fit.vutbr.cz>
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
#include "FeatureVector.h"

FeatureVector::FeatureVector() {
    // Clear source port frequency
    for(auto &i: m_top_src_ports){
        i.first = 0;
    }
}

void FeatureVector::clear() {

    // Set features to default value
    m_last_block_pos = 0;
    memset(m_window, 0, sizeof(m_window));
    m_max_fpm = 0;

    m_rst_echo = 0;
    m_acksyn_dst_unr = 0;

    m_flow_count = 0;
    m_paket_count = 0;
    m_bytes = 0;

    m_packet_squared = 0;
    m_bytes_squared = 0;

    m_unique_src_ports = 0;
    m_unique_dst_ports = 0;
    m_unique_dst_ips = 0;
    m_unique_dst_24_subnets = 0;

    for(auto &i: m_top_src_ports){
        i.first = 0;
    }
    // Set cleared flag
    m_cleared = 1;
}

void FeatureVector::first(const record &rec) {
    m_first_flow = rec.time_first;
    m_min_time_first = rec.time_first;
    m_max_time_last = rec.time_last;
    m_last_block_start_time = rec.time_last;
    update(rec);
}

void FeatureVector::update(const record &rec) {

    // Update start and end time of event
    m_min_time_first = std::min(rec.time_first, m_min_time_first);
    m_max_time_last = std::max(rec.time_last, m_max_time_last);

    // Flag counters
    if(rec.proto == TCP){
        if(rec.flags == ACKSYN){
            m_acksyn_dst_unr += 1;
        } else if (rec.flags == RST){
            m_rst_echo += 1;
        }
    } else if (rec.proto == ICMP){
        if(rec.flags == ECHO_REPLY){
            m_rst_echo += 1;
        } else if(rec.flags == DEST_UNREACHABLE) {
            m_acksyn_dst_unr += 1;
        }
    }

    // Packet and bytes statistics
    m_flow_count += 1;
    uint64_t paket_count = rec.packets;
    if(paket_count <= 0){ // In case of error (invalid value)
        paket_count = 1;
    }
    m_paket_count += paket_count;
    m_packet_squared += paket_count*paket_count;
    float bytes_per_packer = (float) rec.bytes/paket_count;
    m_bytes_squared += bytes_per_packer*bytes_per_packer*paket_count;
    m_bytes += rec.bytes;

    // Unique features
    m_history->update_time(rec.time_last);

    // First 4 items of array identify event, 5th value, 6th unique feature type
    uint32_t data[5] = {rec.src_ip, m_first_flow, rec.proto, rec.dst_ip, DST_IP};
    if(!m_history->containsinsert((const unsigned char *) data, sizeof(data))){
        m_unique_dst_ips++;
    }
    data[3] &= 0xFFFFFF00;
    data[4] = DST_24_SUBNET;
    if(!m_history->containsinsert((const unsigned char *) data, sizeof(data))){
        m_unique_dst_24_subnets++;
    }

    data[3] = rec.dst_port;
    data[4] = DST_PORT;
    if(!m_history->containsinsert((const unsigned char *) data, sizeof(data))){
        m_unique_dst_ports++;
    }

    data[3] = rec.src_port;
    data[4] = SRC_PORT;
    if(!m_history->containsinsert((const unsigned char *) data, sizeof(data))){
        m_unique_src_ports++;
    }

    // Frequent source ports (victim ports)
    m_frequent_src_port(rec.src_port);
    // Maximal flows per minute feature
    m_move_window(rec.time_last);

}

void FeatureVector::m_frequent_src_port(const uint16_t & src_port) {

    bool inserted = false;
    int zero_idx = -1;

    // Search for item or free space (zero)
    for(uint i=0; i < N_TOP_SRC_PORTS_ERROR; i++){
        if(m_top_src_ports[i].first > 0) {
            if(m_top_src_ports[i].second == src_port){
                // Item was found increase counter
                m_top_src_ports[i].first++;
                inserted = true;
                break;
            }
        }  else if(zero_idx == -1) {
            // Mark first zero index
            zero_idx = i;
        }
    }

    // Insert element if there is space or decrease counters
    if(!inserted){
        if(zero_idx != -1){
            // Append item to first free space
            m_top_src_ports[zero_idx].second = src_port;
            m_top_src_ports[zero_idx].first = 1;
        } else {
            // Free space doesn't exist decrease all counters
            for(uint i=0; i < N_TOP_SRC_PORTS_ERROR; i++){
                m_top_src_ports[i].first--;
            }
        }
    }
}

void FeatureVector::m_update_window_stats() {
    // Compute flows per minute in current window and update maximal all-time value
    uint64_t fpm = 0;
    for(uint32_t i = 0; i < MOVING_WINDOW_SIZE; i++){
        fpm += m_window[i];
    }
    m_max_fpm = std::max(m_max_fpm, fpm);
}

void FeatureVector::m_move_window(const uint32_t & time) {
    // Difference between last block start time and time of inserted flow
    int64_t diff = (int64_t) time - m_last_block_start_time;
    // Offset in blocks
    int64_t offset = diff/BLOCK_SIZE;
    int64_t index;

    if (diff > 0 && offset > 0){
        // Window needs to be moved
        // Calculate and update max fpm
        m_update_window_stats();
        // Move start of the window
        if(offset >= MOVING_WINDOW_SIZE){
            // Moving further into to the future
            memset(m_window, 0, sizeof(m_window));
        } else {
            // Moving few steps into the future
            for(int i=1; i <= offset; i++){
                m_window[(m_last_block_pos+i) % MOVING_WINDOW_SIZE] = 0;
            }
        }
        // Updating starting block of window
        m_last_block_start_time = m_last_block_start_time + offset*BLOCK_SIZE;
        m_last_block_pos = (m_last_block_pos + offset) % MOVING_WINDOW_SIZE;
        index = m_last_block_pos;
    } else if (diff < 0) {
        // Appending to blocks further in past
        offset = (diff+1)/BLOCK_SIZE;
        offset--;
        if(std::abs(offset) < MOVING_WINDOW_SIZE){
            index = (int32_t) m_last_block_pos + offset;
            if(index < 0){
                index += MOVING_WINDOW_SIZE;
            }
        } else {
            // Don't update, flow is way behind in the past (outside of window)
            return;
        }
    } else {
        // Flow time is in current block (last block)
        index = m_last_block_pos;
    }

    m_window[index]++;
}

bool sort_by_count(const std::pair<uint64_t, uint16_t> &a,
                   const std::pair<uint64_t ,uint16_t> &b) {
    return a.first>b.first;
}

void FeatureVector::fill_record(ur_template_t *out_template, void *rec) {

    // Finish calculating averages and standard deviations
    float ppf_avg = (float)m_paket_count/m_flow_count;
    float ppf_std = m_packet_squared/m_flow_count;
    ppf_std = std::sqrt(abs(ppf_std - ppf_avg*ppf_avg));

    float bytes_avg = (float)m_bytes/m_paket_count;
    float bytes_std = m_bytes_squared/m_paket_count;
    bytes_std = std::sqrt(abs(bytes_std - bytes_avg*bytes_avg));

    // FPM
    m_update_window_stats();

    // Frequent source ports
    std::sort(m_top_src_ports, m_top_src_ports + N_TOP_SRC_PORTS_ERROR, sort_by_count);
    for(uint i=1; i<N_TOP_SRC_PORTS_REPORT; i++){
        // If there is empty place replace it by previous port
        if(m_top_src_ports[i].first == 0){
            m_top_src_ports[i].second = m_top_src_ports[i-1].second;
        }
    }

    // Set data to UniRec record
    ur_set(out_template, rec, F_POSIX_START, m_min_time_first);
    ur_set(out_template, rec, F_POSIX_END, m_max_time_last);
    ur_set(out_template, rec, F_FLOW_COUNT, m_flow_count);
    ur_set(out_template, rec, F_PACKET_COUNT, m_paket_count);
    ur_set(out_template, rec, F_PPF_AVG, ppf_avg);
    ur_set(out_template, rec, F_PPF_STD, ppf_std);
    ur_set(out_template, rec, F_BYTES, m_bytes);
    ur_set(out_template, rec, F_BYTES_AVG, bytes_avg);
    ur_set(out_template, rec, F_BYTES_STD, bytes_std);
    ur_set(out_template, rec, F_RST, m_rst_echo);
    ur_set(out_template, rec, F_ACKSYN, m_acksyn_dst_unr);

    ur_set(out_template, rec, F_UNIQUE_DST_IPS, m_unique_dst_ips);
    ur_set(out_template, rec, F_UNIQUE_DST_24_SUBNETS, m_unique_dst_24_subnets);
    ur_set(out_template, rec, F_UNIQUE_DST_PORTS, m_unique_dst_ports);
    ur_set(out_template, rec, F_UNIQUE_SRC_PORTS, m_unique_src_ports);
    ur_set(out_template, rec, F_SRC_PORT_1, m_top_src_ports[0].second);
    ur_set(out_template, rec, F_SRC_PORT_1_COUNT, m_top_src_ports[0].first);
    ur_set(out_template, rec, F_SRC_PORT_2, m_top_src_ports[1].second);
    ur_set(out_template, rec, F_SRC_PORT_2_COUNT, m_top_src_ports[1].first);
    ur_set(out_template, rec, F_SRC_PORT_3, m_top_src_ports[2].second);
    ur_set(out_template, rec, F_SRC_PORT_3_COUNT, m_top_src_ports[2].first);

    ur_set(out_template, rec, F_MAX_FPM, m_max_fpm);

}