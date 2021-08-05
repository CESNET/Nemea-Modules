/**
 * \file FeatureVector.h
 * \brief Header file for FeatureVector.cpp
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
#ifndef FEATUREVECTOR_H
#define FEATUREVECTOR_H

#include <unirec/unirec.h>
#include "backscatter_common.h"
#include "fields.h"

/**
 * Moving window size in blocks (used in flows per minute feature)
 */
#define MOVING_WINDOW_SIZE 6
/**
 * Block size in seconds
 */
#define BLOCK_SIZE 10
/**
 * Error for Frequent algorithm, maximal error is equal to  1/\p N_TOP_SRC_PORTS_ERROR
 */
#define N_TOP_SRC_PORTS_ERROR 10 // at most 1/10 (10 %) error
/**
 * How much TOP ports are used in export
 */
#define N_TOP_SRC_PORTS_REPORT 3 // Report only top 3 ports

/**
 * Class representing feature vector
 */
class FeatureVector {
public:
    FeatureVector();
    /**
     * Add first flow to feature vector
     * @param rec Flow record
     */
    void first(const record &rec);
    /**
     * Add flow to feature vector (should be used for all flows expect the first one)
     * @param rec Flow record
     */
    void update(const record &rec);
    /**
     * Clear feature vector, used in case of active export
     */
    void clear();
    /**
     * Fill UniRec record by feature vector content
     * @param out_template Output UniRec template
     * @param rec Output UniRec record
     */
    void fill_record(ur_template_t * out_template, void * rec);
    /**
     * Get count of flows of feature vector
     * @return Number of flows in feature vector
     */
    uint64_t get_count() const;
    /**
     * Get maximal time of all processed flows
     * @return Maximal flow time (from time last)
     */
    uint32_t get_max_time() const;
    /**
     * Get minimal time of all processed flows
     * @return Minimal flow time (from time first)
     */
    uint32_t get_min_time() const;
    /**
     * True (1) if feature vector was previously cleared by active timeout
     * @return
     */
    uint8_t cleared() const;
    static TemporaryHistory *m_history;
private:
    uint32_t m_last_block_start_time; // start time of last block of window
    uint32_t m_last_block_pos = 0; // last block position in window
    uint64_t m_window[MOVING_WINDOW_SIZE] = {0};
    uint64_t m_max_fpm = 0; // Maximal FPM

    uint64_t m_rst_echo = 0; // Number of flows with RST flag or type 0 in case of ICMP
    uint64_t m_acksyn_dst_unr = 0; // Number of flows with ACKSYN flag or type 3 in case of ICMP

    uint32_t m_first_flow; // time of first flow of vector, used to uniquely identify vector in regard to time
    uint32_t m_max_time_last; // maximum of time of all processed flows (time last)
    uint32_t m_min_time_first; // minimum of time of all processed flows (time first)

    uint64_t m_flow_count = 0; // Number of flows
    uint64_t m_paket_count = 0; // Number of packets
    uint64_t m_bytes = 0; // Number og bytes

    float m_packet_squared = 0; // Sum of squared packet count
    float m_bytes_squared = 0; //  Sum of squared bytes

    uint64_t m_unique_src_ports = 0; // Number of unique source ports
    uint64_t m_unique_dst_ports = 0; // Number of unique destination ports
    uint64_t m_unique_dst_ips = 0; // Number of unique destination IPs
    uint64_t m_unique_dst_24_subnets = 0; // Number of unique 24 subnets

    // Storage of frequency and source port pair for Frequent algorithm
    std::pair<uint64_t, uint16_t> m_top_src_ports [N_TOP_SRC_PORTS_ERROR];
    // Cleared flag, has value 1 if event was previously cleared by active timeout
    uint8_t m_cleared = 0;

    /**
     * Move window that measures flows per minute
     * @param time Time of inserted flow
     */
    void m_move_window(const uint32_t & time);
    /**
     * Update window maximal flows per minute
     */
    void m_update_window_stats();
    /**
     * Count frequent source ports (victim ports)
     * @param src_port Source port
     */
    void m_frequent_src_port(const uint16_t & src_port);
};

inline uint64_t FeatureVector::get_count() const {
    return m_flow_count;
}

inline uint32_t FeatureVector::get_max_time() const {
    return m_max_time_last;
}

inline uint32_t FeatureVector::get_min_time() const {
    return m_min_time_first;
}

inline uint8_t FeatureVector::cleared() const {
    return m_cleared;
}

/**
 * Sort pairs used for Frequent algorithm to determine frequent source ports, sorting
 * is done according to first element - frequency
 * @param a First frequency and port pair
 * @param b Second frequency and port pair
 * @return True if first port is more frequent
 */
bool sort_by_count(const std::pair<uint64_t, uint16_t> &a, const std::pair<uint64_t ,uint16_t> &b);

/**
 * Used to distinct different features in one shared feature history
 */
enum unique_feature_type: uint8_t {
    DST_IP=0,
    DST_24_SUBNET,
    DST_PORT,
    SRC_PORT,
};

#endif //FEATUREVECTOR_H
