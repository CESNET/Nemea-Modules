/**
 * \file backscatter_common.h
 * \brief Common constants and functions/methods for this project
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

#ifndef BACKSCATTER_COMMON_H
#define BACKSCATTER_COMMON_H

#include "BloomFilter.hpp"

/**
 * Types of export
 */
enum export_type: uint8_t {
    PASSIVE=2, //!< Passive export - event is inactive
    ACTIVE=4, //!< Active export - event is in memory too long
    FORCED=8, //!< Forced exported - all event in memory are suddenly exported (can happen only at termination of module)
};

/**
 * Some TCP flags values
 */
enum tcp_flags: uint8_t {
    RST = 4,
    RSTACK = 20,
    ACKSYN = 18,
};

/**
 * Some ICMP type values
 */
enum icmp_types: uint8_t {
    ECHO_REPLY = 0,
    DEST_UNREACHABLE = 3,
    SOURCE_QUENCH = 4,
    REDIRECT = 5,
    TIME_EXCEEDED = 11,
    PARAMETER_PROBLEM = 12,
    TIMESTAMP_REPLY = 14,
    INFORMATION_REPLY = 16,
    ADDRESS_MASK_REPLY = 18,
};

/**
 * Protocol values
 */
enum protocol: uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

/**
 * Record representing single flow
 */
struct record {

    uint32_t src_ip;
    uint32_t dst_ip;
    uint64_t bytes;
    uint32_t time_first;
    uint32_t time_last;
    uint32_t packets;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t flags;

    bool operator<(record const &rec) const {
        return time_last > rec.time_last;
    }
};

/**
 * Class representing temporary connection history based on two periodically swapped Bloom filters
 */
class TemporaryHistory {
public:
    /**
     * Constructor of TemporaryHistory
     * @param size Size of Bloom filters (in seconds)
     * @param expected_fps Expected number of inserted element (in flows per second)
     * @param fp Expected false positive rate for Bloom filters (as fraction of 1)
     */
    TemporaryHistory(uint32_t size, uint32_t expected_fps, float fp);
    ~TemporaryHistory();
    /**
     * Add connection (src_ip, dst_ip) to history and update current time
     * @param src_ip Source IP address of flow
     * @param dst_ip Destination IP address of flow
     * @param time Time (last) of flow
     * @return Current time of history
     */
    uint32_t add_connection(const uint32_t &src_ip, const uint32_t &dst_ip, const uint32_t &time);
    /**
     * Check existence of item history
     * @param begin Beginning if data to be inserted
     * @param length Length of data in bytes
     * @return True if history contains item
     */
    bool contains(const unsigned char* begin, const size_t &length);
    /**
     * Check existence of item in history and insert it afterwards
     * @param begin Beginning of data to be inserted/checked
     * @param length Length of data in bytes
     * @return True if history contains item
     */
    bool containsinsert(const unsigned char* begin, const size_t &length);
    /**
     * Update history time - next time will be maximum of current time and \p time
     * @param time Time
     */
    void update_time(const uint32_t &time);
    /**
     * Clear history to initial state
     */
    void clear();
private:
    bloom_filter *m_current; // Current Bloom filter
    bloom_filter *m_next; // Next Bloom filter
    uint32_t m_size; // Size of Bloom filters
    uint32_t m_overlap_point; // Overlap point of current and next Bloom filter
    uint32_t m_max_time = 0; // History time - maximal time of stored flows
    uint32_t m_beginning = 0; //  Time of first flow added to history
    bool m_beginning_set = false;
};

inline bool TemporaryHistory::contains(const unsigned char *begin, const size_t &length) {
    return m_current->contains(begin, length);
}

inline bool TemporaryHistory::containsinsert(const unsigned char *begin, const size_t &length) {
    // Adding to current filter
    bool contains = m_current->containsinsert(begin, length);
    // Add to next if current filter is half-full
    if (m_max_time >= m_beginning + m_overlap_point) {
        m_next->insert(begin, length);
    }
    return contains;
}

#endif //BACKSCATTER_COMMON_H
