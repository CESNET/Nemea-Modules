/**
 * \file backscatter.cpp
 * \brief Extraction of features from backscatter like traffic
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "backscatter.h"
#include "EventTracker.h"


/* **** BEGINNING OF TRAP AND PARAMETER DEFINITIONS **** */

/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
    ipaddr DST_IP, //!< Destination IP
    ipaddr SRC_IP, //!< Source IP
    uint64 BYTES, //!< Number of bytes in flow
    time TIME_FIRST, //!< Time of first packet of flow
    time TIME_LAST, //!< Time of last packet of flow
    uint32 PACKETS, //!< Number of packets in flow
    uint64 PACKET_COUNT, //!< Number packets in event
    uint16 DST_PORT, //!< Destination port or ICMP code + type
    uint16 SRC_PORT,  //!< Source port
    uint8 PROTOCOL, //!< Protocol
    uint8 TCP_FLAGS, //!< TCP flags
    uint32 POSIX_START, //!< Start time of event in POSIX time
    uint32 POSIX_END, //!< End time of event in POSIX time
    uint64 FLOW_COUNT, //!< Number of flows in event
    uint64 RST, //!< Number of flows with RST flag in case of TCP event or number of ICMP flows with type 0
    uint64 ACKSYN, //!< Number of flows with ACKSYN flag in case of TCP event or number of ICMP flows with type 3
    float PPF_AVG, //!< Average number of packets per flow in event
    float PPF_STD, //!< Standard deviation of number of packets per flow in event
    float BYTES_AVG, //!< Average number of bytes per packet in event
    float BYTES_STD, //!< Standard deviation of number of bytes per packet in event
    uint64 UNIQUE_DST_IPS, //!< Number of unique destination IP addresses in event
    uint64 UNIQUE_DST_24_SUBNETS, //!< Number of unique destination /24 subnets in event
    uint64 UNIQUE_DST_PORTS, //!< Number of unique destination ports in event
    uint64 UNIQUE_SRC_PORTS, //!< Number of unique source ports in event
    uint64 MAX_FPM, //!< Maximal flows per minute in event
    uint16 SRC_PORT_1, //!< TOP 1 source port or top ICMP type+code combination
    uint64 SRC_PORT_1_COUNT, //!< Frequency (number) of TOP 1 SRC PORT
    uint16 SRC_PORT_2, //!< TOP 2 source port or top ICMP type+code combination
    uint64 SRC_PORT_2_COUNT, //!< Frequency (number) of TOP 2 SRC PORT
    uint16 SRC_PORT_3, //!< TOP 3 source port or top ICMP type+code ICMP combination
    uint64 SRC_PORT_3_COUNT, //!< Frequency (number) of TOP 3 SRC PORT
    uint8 EXPORT, //!< Type of export of event, first bit is reserved and set to one if event was actively exported before
)

trap_module_info_t *module_info = NULL;

/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Backscatter module", \
        "Extract features from backscatter like traffic. (Oneway flow communication with flags typical for backscatter packets)" \
        ,1,1)


/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
    PARAM('a', "active", "Active timeout in seconds.", required_argument, "uint32")\
    PARAM('p', "passive", "Passive timeout in seconds.", required_argument, "uint32")\
    PARAM('t', "threshold", "Export threshold, feature vector must contain at least stated number of flows to be exported.", required_argument, "uint32") \
    PARAM('r', "c_rate", "Expected rate of incoming records in flows per second (to estimate Bloom history size).", required_argument, "uint32")\
    PARAM('s', "c_history_size", "Size of connection history in seconds.", required_argument, "uint32")\
    PARAM('f', "c_history_fp", "False positive rate for connection history (Bloom filter).", required_argument, "float")\
    PARAM('R', "f_rate", "Expected rate of backscatter like flows per second.", required_argument, "uint32")\
    PARAM('S', "f_history_size", "Size of feature history in seconds.", required_argument, "uint32")\
    PARAM('F', "f_history_fp", "False positive rate for feature history (Bloom filter).", required_argument, "float")\
    PARAM('w', "window", "Left (past) time window for incoming flows in seconds (flows outside of this window are ignored).", required_argument, "uint32") \
    PARAM('W', "Window", "Right (future) time window for incoming flows in seconds (flows outside of this window are ignored).", required_argument, "uint32")\
    PARAM('o', "out", "Periodically flush backscatter buffer after stated number of flows. Default value is zero (no forced flushes). This parameter is used only for test purposes to simulate outages.", required_argument, "uint32")\
    PARAM('P', "print", "Print chosen parameters and performance statistics.", no_argument, "none")\
    //PARAM(char, char *, char *, no_argument  or  required_argument, char *)
/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */


static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1
)

/* **** END OF TRAP AND PARAMETER DEFINITIONS **** */


// Feature history is shared between all events
TemporaryHistory *FeatureVector::m_history = NULL;

int main(int argc, char **argv) {

    /* **** BEGINNING OF TRAP AND PARAMETER INITIALIZATION **** */
    parameters params;
    ur_template_t *in_tmplt, *out_tmplt;
    void *out_rec;
    // Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
    //Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
    // Register signal handler.
    TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
    // Default parameters
    params.active_timeout = ACTIVE_TIMEOUT;
    params.passive_timeout = PASSIVE_TIMEOUT;
    params.threshold = EXPORT_THRESH;
    params.c_fps = FPS;
    params.c_history_size = CONNECTION_HISTORY_SIZE;
    params.c_history_fp = CONNECTION_FP_RATE;
    params.f_fps = FEATURE_FPS;
    params.f_history_size = FEATURE_HISTORY_SIZE;
    params.f_history_fp = FEATURE_FP_RATE;
    params.time_window_negative = TIME_WINDOW_NEGATIVE;
    params.time_window_positive = TIME_WINDOW_POSITIVE;
    params.out = 0;
    params.print = false;

    /*
     * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
     * This macro is defined in config.h file generated by configure script
     */
    signed char opt;
    while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
            case 'a':
                params.active_timeout = std::stoul(optarg);
                break;
            case 'p':
                params.passive_timeout = std::stoul(optarg);
                break;
            case 't':
                params.threshold = std::stoul(optarg);
                break;
            case 'r':
                params.c_fps = std::stoul(optarg);
                break;
            case 's':
                params.c_history_size = std::stoul(optarg);
                break;
            case 'f':
                params.c_history_fp = std::stof(optarg);
                break;
            case 'R':
                params.f_fps = std::stoul(optarg);
                break;
            case 'S':
                params.f_history_size = std::stoul(optarg);
                break;
            case 'F':
                params.f_history_fp = std::stof(optarg);
                break;
            case 'w':
                params.time_window_negative = std::stoul(optarg);
                break;
            case 'W':
                params.time_window_positive = std::stoul(optarg);
                break;
            case 'P':
                params.print = true;
                break;
            case 'o':
                params.out = std::stoul(optarg);
                break;
            default:
                fprintf(stderr, "Invalid arguments.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
        }
    }

    params.bs_buffer_size = params.f_fps*params.c_history_size;

    if (params.print) {
        std::cout << "Active timeout: " << params.active_timeout << std::endl;
        std::cout << "Passive timeout: " << params.passive_timeout << std::endl;
        std::cout << "Backscatter buffer size: " << params.bs_buffer_size << std::endl;
        std::cout << "Export threshold: " << params.threshold << std::endl;
        std::cout << "Expected flows per second: " << params.c_fps << std::endl;
        std::cout << "Expected number of backscatter like flows per second: " << params.f_fps << std::endl;
        std::cout << "Connection history size in seconds: " << params.c_history_size << std::endl;
        std::cout << "Connection history size in records: " << params.c_history_size*params.c_fps*2 << std::endl;
        std::cout << "Connection history false positive rate: " << params.c_history_fp << std::endl;
        std::cout << "Feature history size in seconds: " << params.f_history_size << std::endl;
        std::cout << "Feature history size in records: " << params.f_history_size*params.f_fps*HISTORY_FEATURES*2 << std::endl;
        std::cout << "Feature history false positive rate: " << params.f_history_fp << std::endl;
        std::cout << "Time window negative: " << params.time_window_negative << std::endl;
        std::cout << "Time window positive: " << params.time_window_positive << std::endl;
    }

    // Create UniRec templates
    in_tmplt = ur_create_input_template(0,
                                        "DST_IP,SRC_IP,BYTES,TIME_FIRST,TIME_LAST,PACKETS,DST_PORT,SRC_PORT,PROTOCOL,TCP_FLAGS",
                                        NULL);

    if (in_tmplt == NULL) {
        fprintf(stderr, "Error: Input template could not be created.\n");
        return -1;
    }

    out_tmplt = ur_create_output_template(0,
                                          "SRC_IP,PROTOCOL,POSIX_START,POSIX_END,FLOW_COUNT,PACKET_COUNT,PPF_AVG,PPF_STD, "
                                          "BYTES,BYTES_AVG,BYTES_STD,RST,ACKSYN,MAX_FPM,UNIQUE_DST_IPS,UNIQUE_DST_PORTS,UNIQUE_SRC_PORTS,"
                                          "UNIQUE_DST_24_SUBNETS, SRC_PORT_1,SRC_PORT_1_COUNT, SRC_PORT_2,"
                                          " SRC_PORT_2_COUNT, SRC_PORT_3, SRC_PORT_3_COUNT, EXPORT",
                                          NULL);

    if (out_tmplt == NULL) {
        ur_free_template(in_tmplt);
        fprintf(stderr, "Error: Output template could not be created.\n");
        return -1;
    }

    // Allocate memory for output record
    out_rec = ur_create_record(out_tmplt, 0);
    if (out_rec == NULL) {
        ur_free_template(in_tmplt);
        ur_free_template(out_tmplt);
        fprintf(stderr, "Error: Memory allocation problem (output record).\n");
        return -1;
    }

    /* **** END OF TRAP AND PARAMETER INITIALIZATION **** */

    // Ip structures
    ip_addr_t *src_ip = NULL;
    ip_addr_t *dst_ip = NULL;

    // Feature and connection history
    FeatureVector::m_history = new TemporaryHistory(params.f_history_size, params.f_fps*HISTORY_FEATURES, params.f_history_fp);
    TemporaryHistory history(params.c_history_size, params.c_fps, params.c_history_fp);

    // Track backscatter events/feature vectors and send them using libtrap
    EventTracker etracker(out_tmplt, out_rec, params.active_timeout, params.passive_timeout, params.threshold);

    // Buffer for BS like flows to create delay (match biflows)
    std::vector<record> buffer_container;
    buffer_container.reserve(params.bs_buffer_size);
    std::priority_queue<record, std::vector<record>> buffer(std::less<record>(), buffer_container);

    // Maximal received flow time
    uint32_t max_time = 0;
    // True if previously received flow was skipped
    bool skipped_prev = false;
    // Number of continuously skipped flows
    uint32_t continuously_skipped = 0;
    // Number of continuously skipped flows after which history, buffer and time is reset
    uint32_t time_reset_threshold = params.c_history_size*params.c_fps;
    // Runtime statistics
    statistics stats;
    // Time difference stats
    double avg_diff = 0;
    int64_t min_diff = UINT32_MAX;
    int64_t max_diff = 0;
    double std_diff = 0;
    // Simulating outage
    bool outage = false;
    uint32_t outage_sizes[4] = {40000000, 20000000, 80000000, 0};
    uint32_t chosen_outage_size = 0;
    uint32_t outage_duration = 0;
    uint32_t outage_counter = 0;

    /* 
    * CESNET address range used as virtual telescope, must be same as in backscatter_classifier module!
    * If networks differ statistical inference in backscatter_classfier module may not be correct (size of attack
    * is determined by size of monitored network)
    */
    uint32_t CESNET_NET[18] = {0x92660000, 0x93e40000, 0x93fb0000, 0x93200000, 0x9ec20000, 0x9ec40000, 0xa0d80000,
                                0xc1547400, 0xc154a000, 0xc154c000, 0xc1542000, 0xc1543500, 0xc1543700, 0xc1543800,
                                0xc1545000, 0xc3710000, 0xc3b24000, 0x4e808000};
 
    uint32_t CESNET_NET_MASK[18] = {0xffff0000, 0xfffc0000, 0xffff0000, 0xfffe0000, 0xffff0000, 0xffff0000, 0xfffe0000,
                                    0xfffffe00, 0xfffff000, 0xffffe000, 0xfffff000, 0xffffff00, 0xffffff00, 0xfffff800,
                                    0xfffffc00, 0xffff0000, 0xffffe000, 0xffff8000};
    size_t outside=0;


    try {
        /* **** BEGINNING OF MAIN LOOP **** */
        while (!stop) {

            /* **** BEGINNING OF RECEIVING MESSAGE VIA TRAP INTERFACE **** */
            // TRAP dependent variables
            int ret; // return value
            const void *in_rec; // input record
            uint16_t in_rec_size; // input record size
            // Receive data from input interface 0.
            // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
            ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
            // Handle possible errors
            TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

            // Check size of received data
            if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
                if (in_rec_size <= 1) {
                    break; // End of data (used for testing purposes)
                } else {
                    fprintf(stderr,
                            "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                            ur_rec_fixlen_size(in_tmplt), in_rec_size);
                    break;
                }
            }
            /* **** END OF RECEIVING MESSAGE VIA TRAP INTERFACE **** */

            // Only IPv4 support
            src_ip = &ur_get(in_tmplt, in_rec, F_SRC_IP);
            dst_ip = &ur_get(in_tmplt, in_rec, F_DST_IP);
            if (ip_is4(src_ip) != 1) {
                stats.ipv6++;
                continue;
            }

            // Convert addresses to int
            uint32_t src_ip4 = ip_get_v4_as_int(src_ip);
            uint32_t dst_ip4 = ip_get_v4_as_int(dst_ip);

            bool in_cesnet = false;
            for (uint i = 0; i < 18; i++) {
                if (((CESNET_NET_MASK[i] & dst_ip4) == CESNET_NET[i]) || ((CESNET_NET_MASK[i] & src_ip4) == CESNET_NET[i])) {
                    in_cesnet = true;
                    break;
                }
            }
            if (!in_cesnet) {
                 outside++;
                 continue;
            }


            // Total received IPv4 flows
            stats.total_flows++;
            uint32_t time_last = ur_time_get_sec(ur_get(in_tmplt, in_rec, F_TIME_LAST));

            /* **** BEGINNING of incoming flow time check **** */
            if (max_time != 0) {
                int64_t diff = (int64_t) time_last - max_time;
                avg_diff += diff;
                std_diff += diff*diff;
                min_diff = std::min(min_diff, diff);
                max_diff = std::max(max_diff, diff);
                if((diff < 0 && -diff > params.time_window_negative) || (diff > 0 && diff > params.time_window_positive)) {
                    // Number of continuous flows that are outside of monitored time window
                    if (skipped_prev) {
                        continuously_skipped++;
                    } else {
                        continuously_skipped = 1;
                        skipped_prev = true;
                    }
                    /*
                     * Multiple flows are outside of the window (data stream was probably disturbed/stopped),
                     * data structures must be cleared
                     */
                    if (continuously_skipped >= time_reset_threshold) {

                        // Flush buffer and clear history
                        while (!buffer.empty()) {
                            buffer.pop();
                        }
                        history.clear();
                        max_time = time_last;
                        stats.time_resets++;
                        skipped_prev = false;
                    }
                    stats.skipped_flows++;
                    continue;
                }
            }
            skipped_prev = false;
            /* **** END of incoming flow time check **** */
            // Set current time
            max_time = std::max(max_time, time_last);

            uint8_t flags = ur_get(in_tmplt, in_rec, F_TCP_FLAGS);
            uint8_t proto = ur_get(in_tmplt, in_rec, F_PROTOCOL);

            // Insert communication IPs to Bloom history
            if (!(proto == TCP && (flags == RST || flags == RSTACK))) {
                uint32_t hist_time = history.add_connection(src_ip4, dst_ip4, time_last);
                // Synchronization of backscatter buffer and history
                while (!buffer.empty() && (buffer.top().time_last + params.c_history_size <= hist_time)) {
                    process_buffer_record(history, buffer, etracker, stats);
                }
            }

            // Simulating outage (incorrect filtering)
            if(params.out != 0 && (stats.total_flows % params.out == 0 || outage)){
                if(!outage){
                    chosen_outage_size = outage_sizes[outage_counter % 4];
                    outage = true;
                    outage_duration = 0;
                    outage_counter++;
                }
                outage_duration++;
                // Process buffer without direction check
                while(!buffer.empty()) {
                    record rec = buffer.top();
                    etracker.add(rec);
                    buffer.pop();
                }
                // Go back to normal function
                if(outage_duration >= chosen_outage_size){
                    outage = false;
                }
            }

            uint16_t src_port = ur_get(in_tmplt, in_rec, F_SRC_PORT);
            uint16_t dst_port = ur_get(in_tmplt, in_rec, F_DST_PORT);

            // In case of ICMP set type to TCP flags and dst_port, src_port contains both code and type
            if (proto == ICMP) {
                // ICMP code and type
                src_port = dst_port;
                // ICMP type
                dst_port = dst_port >> 8;
                flags = dst_port;
            }

            // Add backscatter like flows to buffer
            if (is_bs_like(proto, flags)) {
                // Add record to buffer if it is not full
                if (buffer.size() >= params.bs_buffer_size) {
                    stats.full_bs_buffer++;
                } else {
                    // Fill buffer
                    buffer.push({src_ip4, dst_ip4, ur_get(in_tmplt, in_rec, F_BYTES),
                                 ur_time_get_sec(ur_get(in_tmplt, in_rec, F_TIME_FIRST)),
                                 time_last, ur_get(in_tmplt, in_rec, F_PACKETS), src_port,
                                 dst_port, proto, flags});
                }
            }

        }
        /* **** END MAIN LOOP **** */

        // Force export of all events in memory (but buffer is left untouched)
        etracker.force_export();

    } catch (trap_send_exception &e) {
        fprintf(stderr, "Error: %s\n", e.what());
    }

    // Print statistics
    if (params.print) {
        std::cout << std::endl;
        std::cout << "Flows: " << stats.total_flows << std::endl;
        std::cout << "Skipped: " << stats.skipped_flows << std::endl;
        std::cout << "Time resets: " << stats.time_resets << std::endl;
        std::cout << "TCP backscatter like flow count: " << stats.bs_like_flows_tcp << std::endl;
        std::cout << "TCP backscatter like flow count without bidirectional host communication: "
                  << stats.bs_like_flows_oneway_tcp << std::endl;
        std::cout << "ICMP backscatter like flow count: " << stats.bs_like_flows_icmp << std::endl;
        std::cout << "ICMP backscatter like flow count without bidirectional host communication: "
                  << stats.bs_like_flows_oneway_icmp << std::endl;
        std::cout << "Total events: " << etracker.m_total_events << std::endl;
        std::cout << "Total events TCP: " << etracker.m_total_events_tcp << std::endl;
        std::cout << "Total events ICMP: " << etracker.m_total_events_icmp << std::endl;
        std::cout << "Events in memory: " << etracker.in_memory() << std::endl;
        std::cout << "Freed actively: " << etracker.m_active_freed << std::endl;
        std::cout << "Freed passively: " << etracker.m_passive_freed << std::endl;
        std::cout << "Exported events: " << etracker.m_exp_icmp + etracker.m_exp_tcp << std::endl;
        std::cout << "Exported events TCP: " << etracker.m_exp_tcp << std::endl;
        std::cout << "Exported events ICMP: " << etracker.m_exp_icmp  << std::endl;
        std::cout << "Timeout sends: " << etracker.m_send_timeout_reached << std::endl;
        std::cout << "Full buffer: " << stats.full_bs_buffer << std::endl;
        std::cout << "Ipv6: " << stats.ipv6 << std::endl;
        std::cout << "Simulated outages: " << outage_counter << std::endl;

        avg_diff = avg_diff/stats.total_flows;
        std::cout << "Average time difference: " << avg_diff << std::endl;
        std_diff = std_diff/stats.total_flows;
        std_diff = std::sqrt(std_diff - avg_diff*avg_diff);
        std::cout << "Standard deviation of time difference: " << std_diff << std::endl;
        std::cout << "Minimal time difference: " << min_diff << std::endl;
        std::cout << "Maximal time difference: " << max_diff << std::endl;
        std::cout << std::endl;
        std::cout << "Outside: " << outside << std::endl;
    }

    // Terminating message
    if (!stop) {
        char dummy[1] = {0};
        trap_send(0, dummy, 0);
    }

    /* **** Cleanup **** */

    // Do all necessary cleanup in libtrap before exiting
    TRAP_DEFAULT_FINALIZATION();

    // Release allocated memory for module_info structure
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    // Free unirec templates and output record
    ur_free_record(out_rec);
    ur_free_template(in_tmplt);
    ur_free_template(out_tmplt);
    ur_finalize();

    delete FeatureVector::m_history;

    return 0;
}

