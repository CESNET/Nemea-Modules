/**
 * \file EventTracker.h
 * \brief Header file for EventTracker.cpp
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

#ifndef EVENTTRACKER_H
#define EVENTTRACKER_H

#include <queue>
#include <vector>
#include <unordered_map>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "backscatter_common.h"
#include "FeatureVector.h"
#include "fields.h"

/**
 * Unable to send event exception
 */
struct trap_send_exception: public std::exception
{
    const char * what () const throw ()
    {
        return "Error while sending feature vector";
    }
};

/**
 * Event id
 */
struct event_id {
    uint32_t ip; //!< IP address of backscatter source (potential victim)
    uint8_t proto; //!< Protocol

    bool operator==(const event_id &id) const {
        return ip == id.ip && proto == id.proto;
    }

};

namespace std {
    template <>
    struct hash<event_id> {
        /**
         * Event id hash
         * @param id Event id
         * @return hash of id
         */
        std::size_t operator()(const event_id& id) const noexcept {
            return hash<uint32_t>()(id.ip ^ ((uint32_t) id.proto << 24));
        }
    };
}
/**
 * Calendar notification in order to check passive timout
 */
struct calendar_item {
public:
    event_id id;
    uint32_t time;

    /**
     * Notification
     * @param id Event id
     * @param time Notification time
     */
    calendar_item(event_id id, uint32_t time) :
            id(id), time(time) {
    }

    bool operator<(calendar_item const &i) const {
        return time > i.time;
    }

};

/**
 * Track events and export/send them via TRAP
 */
class EventTracker {
public:
    /**
     * Constructor of EventTracker
     * @param out_template Output UniRec template
     * @param out_rec Output UniRec record
     * @param active Active timeout
     * @param passive Passive timeout
     * @param threshold Export threshold, event below this threshold will not be exported
     */
    EventTracker(ur_template_t *out_template, void *out_rec, uint32_t active, uint32_t passive, uint32_t threshold):
            m_out_template(out_template), m_out_rec(out_rec), m_active_t(active), m_passive_t(passive),
            m_threshold(threshold) {};
    /**
     * Get current number of events in memory
     * @return Current number of events in memory
     */
    size_t in_memory() const;
    /**
     * Force export of events currently in memory
     */
    void force_export();
    /**
     * Add record (flow) to existing event or create new one, export event if necessary
     * @param rec Flow record
     */
    void add(const record &rec);
    // Statistics
    size_t m_total_events = 0; //!< Total number of events
    size_t m_total_events_tcp = 0; //!< Total number of events
    size_t m_total_events_icmp = 0; //!< Total number of events
    size_t m_exp_tcp = 0; //!< Number of exported TCP events
    size_t m_exp_icmp = 0; //!< Number of exported ICMP events
    size_t m_passive_freed = 0; //!< Total number of passively freed events
    size_t m_active_freed = 0; //!< Total number of actively freed events
    size_t m_send_timeout_reached = 0; //!< Number of times event could not be exported due to TRAP timeout
protected:
    ur_template_t *m_out_template; // UniRec output template
    void *m_out_rec; // UniRec output record
    uint32_t m_active_t; // Active timeout
    uint32_t m_passive_t; // Passive timeout
    uint32_t m_threshold; // Export threshold
    std::unordered_map<event_id, FeatureVector> m_events; // Event table
    std::priority_queue<calendar_item, std::vector<calendar_item>> m_calendar; // Calendar used for checking passive timeout
    uint32_t m_current_t = 0; // Local time for this class
    bool m_beginning_set = false; // Initial time not set
    /**
     * Export event
     * @param id Event id
     * @param exp Export type
     */
    void m_export(const event_id &id, export_type exp);
};

inline size_t EventTracker::in_memory() const {
    return m_events.size();
}

#endif //EVENTTRACKER_H
