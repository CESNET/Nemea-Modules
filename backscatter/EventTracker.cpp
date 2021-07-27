/**
 * \file EventTracker.cpp
 * \brief Class representing handling of events (passive/active timeouts) and their export using libtrap
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
#include "EventTracker.h"
#include <iostream>


void EventTracker::m_export(const event_id &id, export_type exp) {

    FeatureVector &v = m_events[id];

    if(v.get_count() >= m_threshold){
        if(id.proto == TCP){
            m_exp_tcp++;
        } else if(id.proto == ICMP){
            m_exp_icmp++;
        }
        int ret;
        // Fill output record
        ur_set(m_out_template, m_out_rec, F_SRC_IP, ip_from_int(id.ip));
        ur_set(m_out_template, m_out_rec, F_PROTOCOL, id.proto);
        ur_set(m_out_template, m_out_rec, F_EXPORT, exp | v.cleared());
        v.fill_record(m_out_template, m_out_rec);
        // Send record to interface 0.
        // Block if ifc is not ready (unless a timeout is set using trap_ifcctl)
        ret = trap_send(0, m_out_rec, ur_rec_fixlen_size(m_out_template));
        // Handle possible errors
        TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, m_send_timeout_reached++, throw trap_send_exception());
    }
}

void EventTracker::force_export() {
    for(auto v: m_events){
        m_export(v.first, FORCED);
    }
}

void EventTracker::add(const record &rec) {

    // Setting current time as max of previous times
    if (!m_beginning_set) {
        m_current_t = rec.time_last;
        m_beginning_set = true;
    }
    // Passive timeout
    bool stop_listing = false;
    // Update EventTracker time
    if (m_current_t < rec.time_last) {
        m_current_t = rec.time_last;
    } else {
        stop_listing = true;
    }

    while (!stop_listing && !m_calendar.empty()) {
        // Check top entry
        calendar_item notification = m_calendar.top();
        auto event_iter = m_events.find(notification.id);
        if (event_iter == m_events.end()) {
            // Event was already exported
            m_calendar.pop();
        } else {
            if (notification.time + m_passive_t < m_current_t) {
                // Timeout has passed, check event
                m_calendar.pop();
                if (m_events[notification.id].get_max_time() + m_passive_t < m_current_t) {
                    // Record is inactive
                    m_passive_freed++;
                    m_export(notification.id, PASSIVE);
                    m_events.erase(notification.id);
                } else {
                    // Record is not inactive, add new check event
                    m_calendar.push(calendar_item(notification.id, m_events[notification.id].get_max_time()));
                }
            } else {
                stop_listing = true;
            }
        }
    }

    event_id id = {rec.src_ip, rec.proto};

    // Active timeout
    if (m_events[id].get_count() > 0 && m_events[id].get_min_time() + m_active_t < m_current_t) {
        m_export(id, ACTIVE);
        m_events[id].clear();
        m_active_freed++;
    }

    // Entry not yet in table
    if (m_events[id].get_count() == 0) {
        // Increase total number of events if events was not previously exported actively
        if(!m_events[id].cleared()){
            m_total_events++;
            if(id.proto == TCP){
                m_total_events_tcp++;
            } else if(id.proto == ICMP){
                m_total_events_icmp++;
            }
        }
        // Initialize entry
        m_events[id].first(rec);
        m_calendar.push(calendar_item(id, rec.time_last));
    } else {
        // Update entry
        m_events[id].update(rec);
    }

}
