/**
 * \file backscatter_common.cpp
 * \brief Implementation of common functions/methods for backscatter module
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
#include "backscatter_common.h"

TemporaryHistory::TemporaryHistory(uint32_t size, uint32_t expected_fps, float fp) {
    m_size = size * 2; // allocate twice as big bloom filter (overlap is equal to size)
    m_overlap_point = size;
    bloom_parameters param;
    param.projected_element_count = (uint64_t) m_size * expected_fps;
    param.false_positive_probability = fp;
    param.compute_optimal_parameters();
    m_current = new bloom_filter(param);
    m_next = new bloom_filter(param);
}

uint32_t TemporaryHistory::add_connection(const uint32_t &src_ip, const uint32_t &dst_ip, const uint32_t &time) {

    uint32_t conn[2] = {src_ip, dst_ip};

    update_time(time);
    // Adding to current filter
    m_current->insert((const unsigned char *) conn, sizeof(conn));
    // Add to next if current filter is half-full
    if (m_max_time >= m_beginning + m_overlap_point) {
        m_next->insert((const unsigned char *) conn, sizeof(conn));
    }

    return m_max_time;
}


void TemporaryHistory::update_time(const uint32_t &time) {

    m_max_time = std::max(time, m_max_time);

    if (!m_beginning_set) {
        m_beginning = time;
        m_beginning_set = true;
    }

    // If current filter is full (time has passed), swap it with next filter (which is half-full now)
    if (m_max_time > m_beginning + m_size) {
        std::swap(m_current, m_next);
        m_next->clear();
        m_beginning += m_overlap_point;
    }
}

void TemporaryHistory::clear() {
    m_next->clear();
    m_current->clear();
    m_beginning_set = false;
    m_max_time = 0;
}

TemporaryHistory::~TemporaryHistory() {
    delete m_current;
    delete m_next;
}
