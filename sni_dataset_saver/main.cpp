/**
 * \file main.cpp
 * \brief Lookup for user specific TLS SNI indicator and send matched flow to output ifc. 
 * \author Pavel Siska <siska@cesnet.cz>
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
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <chrono> 
#include <ctime>

#include <getopt.h>
#include <signal.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "htrie_map.h"
#include "rapidcsv.h"
#include "fields.h"
#include "sampler.h"
#include "json.hpp"
#include "sni.h"

/**
 * Statically defined fields always used by module
 */
UR_FIELDS ( 
    time TIME_FIRST,
    time TIME_LAST,
    string TLS_SNI,
    string TLS_SNI_STATS,
)

#define SNI_IFC   0
#define STATS_IFC 1

#define REQUIRED_INPUT_TEMPLATE "TLS_SNI"

#define WINDOW_SIZE 5

#define MODULE_BASIC_INFO(BASIC) \
    BASIC("tls_sni_capture", "Aggregate and classify IP addresses.", 1, 2)

#define MODULE_PARAMS(PARAM) \
    PARAM('f', "filename", "Domains filename", required_argument, "string") \
    PARAM('t', "timeout", "Sampling timeout (sec)", required_argument, "int") \
    PARAM('s', "stats_file", "Stats string file", required_argument, "string")


trap_module_info_t *module_info = NULL;

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * @brief Loads domain names from file.
 *
 * @return int 1 - error, 0 - success
 */
static int
load_sni_domains_file(const std::string& filename, std::vector<Sni_record>& sni_records)
{
    rapidcsv::Document doc(filename);

    std::vector<std::string> tags = doc.GetColumn<std::string>("Tag");
    std::vector<std::string> domains = doc.GetColumn<std::string>("Merged Domains");
    if (!tags.size() || tags.size() != domains.size()) {
        std::cerr << "Invalid format of csv file." << std::endl;
        return 1;
    }

    uint32_t idx = 0;
    for (auto& tag : tags) {
        sni_records.emplace_back(Sni_ctx(tag, domains[idx]));
        idx++;
    }

    return 0;
}

static int
load_stats_file(const std::string& filename, std::vector<Sni_record>& sni_records)
{
    std::ifstream f(filename);
    if (!f.good()) {
        std::cerr << "Stats file does not exist." << std::endl;
        return 1;
    }
    
    nlohmann::json json_stats;
    rapidcsv::Document doc(filename, rapidcsv::LabelParams(-1, -1));

    std::vector<std::string> tags = doc.GetColumn<std::string>(2);
    if (tags.empty()) {
        std::cerr << "Stats file is empty." << std::endl;
        return 1;
    }

    json_stats = nlohmann::json::parse(tags.front());
    
    for (auto& it : json_stats.items()) {
        for (auto& sni_record : sni_records) {
            if (it.key().compare(sni_record.ctx.tag) == 0) {
                sni_record.set_total_counter(it.value());
            }
        }
    }

    return 0;
}



/**
 * @brief Send flow record to output interface. 
 * 
 * @param tmplt_out  Output template
 * @param rec        Flow data
 * @param ifc_idx    Interface index
 * @return true   Success.
 * @return false  Send timeouted or error occurred.
 */
static bool 
send_record(ur_template_t *tmplt_out, const void *rec, uint16_t ifc_idx)
{
    constexpr int max_try = 3;
    int ret;

    for (int i = 0; i < max_try; i++) {
        ret = trap_send(ifc_idx, rec, ur_rec_size(tmplt_out, rec));
        TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
        return true;
    }
    std::cerr << "Cannot send record due to error or timeout." << std::endl;
    return false;
}

/**
 * @brief Look up for TLS SNI in domain names (trie_map) 
 *
 * @param tls_sni   TLS SNI identificator
 */
static Sni_record *
trie_domain_lookup(tsl::htrie_map<char, std::pair<bool, Sni_record *>>& trie_map, const std::string& tls_sni)
{
    std::string reverse_tls_sni;


    reverse_tls_sni = std::string(tls_sni.rbegin(),tls_sni.rend());
    auto trie_item = trie_map.longest_prefix(reverse_tls_sni);
    if (trie_item == trie_map.end())
        return nullptr;
    
    auto trie_pair = trie_item.value();

    if (reverse_tls_sni.compare(trie_item.key()) == 0) {
        return trie_pair.second;
    } else {
        if (trie_pair.first 
            && reverse_tls_sni.size() > trie_item.key().size() 
            && reverse_tls_sni.at(trie_item.key().size()) == '.') {
            return trie_pair.second;
        }
    }

    return nullptr;
}

/**
 * @brief Change format of output interfaces.
 * 
 * @param tmplt_out Output template
 * @return int 0 - success, 1 - error
 */
static int
change_trap_format(ur_template_t **tmplt_out)
{
    const char *spec;
    const char *f_names;
    uint8_t data_fmt = TRAP_FMT_UNKNOWN;

    /* Get new data format used on input interface. */
    if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
        std::cerr << "Error: Get of input template failed." << std::endl;
        return 1;
    }

    f_names = ur_ifc_data_fmt_to_field_names(spec);
    if (f_names == NULL) {
        std::cerr << "Error: Cannot convert data format to field names" << std::endl;
        return 1;
    }

    ur_free_template(*tmplt_out);
    *tmplt_out = ur_create_output_template(0, f_names, NULL);
    if (*tmplt_out == NULL) {
        std::cerr << "Error: Output template could not be created." << std::endl;
        return 1;
    }

    return 0;
}

int get_pos(size_t total_size, int current_idx)
{
    return current_idx * (100.0 / total_size);
}

/**
 * @brief Update SNI stats and create string with stats in json
 */
static void 
update_stats(std::vector<Sni_record>& sni_records, std::string& stats_msg)
{
    using sni_pair = std::pair<std::string, Sni_record *>;
    std::vector<sni_pair> sorted_sni_records;
    sorted_sni_records.reserve(sni_records.size());
    for (auto& sni_record : sni_records) {
        sorted_sni_records.emplace_back(sni_record.ctx.tag, &sni_record);
    }

    std::stable_sort(std::begin(sorted_sni_records), std::end(sorted_sni_records), 
        [](const sni_pair& a, const sni_pair& b) { return a.second->get_total_counter() < b.second->get_total_counter(); });

    nlohmann::json json;
    size_t sni_record_size = sorted_sni_records.size();
    int idx = 0;

    // hard-coded sampling
    for (const auto& it: sorted_sni_records) {
        int pos = get_pos(sni_record_size, idx);
        if (pos <= 25) {
            it.second->disable_sampling();
        } else if (pos <= 30) {
            it.second->enable_sampling(2);
        } else if (pos <= 40) {
            it.second->enable_sampling(3);
        } else if (pos <= 50) {
            it.second->enable_sampling(4);
        } else if (pos <= 70) {
            it.second->enable_sampling(6);
        } else if (pos <= 95) {
            it.second->enable_sampling(9);
        } else {
            it.second->enable_sampling(15);
        }
        idx++;
        json[it.second->ctx.tag] = it.second->get_total_counter();
    }
    stats_msg = json.dump();
}

static void
get_window_timestamps(time_t& begin, time_t& end)
{
    std::time_t tt = std::chrono::system_clock::system_clock::to_time_t(std::chrono::system_clock::system_clock::now());
    struct std::tm *ptm = std::localtime(&tt);

    ptm->tm_sec = 0;
    end = mktime(ptm) << 32;
    ptm->tm_min -= WINDOW_SIZE;
    begin = mktime(ptm) << 32;
}

/**
 * @brief Set refresh_stats to true every timeout min
 * 
 * @param timeout time
 */
static void 
stats_thread(std::vector<Sni_record>* sni_records)
{
    void *rec_out = NULL;
    ur_template_t *tmplt_stats = NULL;
    std::string stats_msg;
    time_t begin;
    time_t end;

    tmplt_stats = ur_create_output_template(STATS_IFC, "TIME_FIRST,TIME_LAST,TLS_SNI_STATS", NULL);
    if (tmplt_stats == NULL) {
        std::cerr << "Error: Output template could not be created." << std::endl;
        stop = true;
        return;
    }

    rec_out = ur_create_record(tmplt_stats, UR_MAX_SIZE);
    if (rec_out == NULL) {
        std::cerr << "Error: Output record could not be created." << std::endl;
        ur_free_template(tmplt_stats);
        stop = true;
        return;
    }

    while (!stop) {
        std::time_t tt = std::chrono::system_clock::system_clock::to_time_t(std::chrono::system_clock::system_clock::now());
        struct std::tm *ptm = std::localtime(&tt);
        while (++ptm->tm_min % WINDOW_SIZE != 0)
            ptm->tm_min++;
        ptm->tm_sec = 0;
        std::this_thread::sleep_until(std::chrono::system_clock::system_clock::from_time_t(mktime(ptm)));

        update_stats(*sni_records, stats_msg);
        get_window_timestamps(begin, end);
        ur_set(tmplt_stats, rec_out, F_TIME_FIRST, begin);
        ur_set(tmplt_stats, rec_out, F_TIME_LAST, end);
        ur_set_string(tmplt_stats, rec_out, F_TLS_SNI_STATS, stats_msg.c_str());
        send_record(tmplt_stats, rec_out, STATS_IFC);
        trap_send_flush(STATS_IFC);
    }

    free(rec_out);
    trap_send_flush(STATS_IFC);
    ur_free_template(tmplt_stats);
}

/**
 * @brief Flow reading loop.
 * 
 * @param trie_map  Domain names
 * @param tmplt_in  Input template
 * @return int 0 - success, 1 - error
 */
static int
do_mainloop(tsl::htrie_map<char, std::pair<bool, Sni_record *>>& trie_map, ur_template_t *tmplt_in)
{
    ur_template_t *tmplt_out = NULL;
    Sni_record* sni_record;
    const void *rec_in;
    uint16_t rec_size;
    int ret;

    time_t first;
    time_t last;

    while (stop != true) {
        ret = TRAP_RECEIVE(SNI_IFC, rec_in, rec_size, tmplt_in);
        TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
        if (rec_size <= 1 || (ret == TRAP_E_FORMAT_CHANGED && change_trap_format(&tmplt_out))) {
            break;   
        }

        std::string tls_sni(ur_get_ptr(tmplt_in, rec_in, F_TLS_SNI), ur_array_get_elem_cnt(tmplt_in, rec_in, F_TLS_SNI));
        sni_record = trie_domain_lookup(trie_map, tls_sni);

        first = ur_time_get_sec(ur_get(tmplt_in, rec_in, F_TIME_FIRST));
        last = ur_time_get_sec(ur_get(tmplt_in, rec_in, F_TIME_LAST));

        if (!sni_record || sni_record->should_be_sampled(first, last)) {
            continue;
        }

        send_record(tmplt_out, rec_in, SNI_IFC);
    }

    trap_send_flush(SNI_IFC);
    ur_free_template(tmplt_out);
    stop = true;
    return 0;
}


static void
initiliaze_trie(tsl::htrie_map<char, std::pair<bool, Sni_record *>>& trie_map, std::vector<Sni_record>& sni_records_vector)
{
    for (auto& sni_record: sni_records_vector) {
        for (auto& it: sni_record.ctx.reverse_domains) {
            trie_map.insert(it.first, std::make_pair(it.second, &sni_record));
        }
    }
}

int 
main(int argc, char **argv)
{
    tsl::htrie_map<char, std::pair<bool, Sni_record *>> trie_map;
    std::vector<Sni_record> sni_records;
    ur_template_t *tmplt_in = NULL;
    std::string filename;
    std::string stats_filename;
    char opt;

    // Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO.
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

    // Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

    while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
        case 'f':
            filename = optarg;
            break;
        case 's':
            stats_filename = optarg;
            break;
        case 't':
            Sampler::set_timeout(std::strtoul(optarg, NULL, 0));
            break;
        default:
            std::cerr << "Invalid argument " << opt << ", skipped..." << std::endl;
        }
    }

    std::thread thread(stats_thread, &sni_records);

    if (filename.empty()) {
        std::cerr << "Domains filename argument is not set." << std::endl;
        goto failure;
    }

    if (load_sni_domains_file(filename, sni_records)) {
        goto failure;
    }

    initiliaze_trie(trie_map, sni_records);

    if (!stats_filename.empty()) {
        load_stats_file(stats_filename, sni_records);
    }

    /* Set timeouts. */
    trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, 1000000);
    trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);

    trap_set_required_fmt(0, TRAP_FMT_UNIREC, NULL);

    tmplt_in = ur_create_input_template(0, REQUIRED_INPUT_TEMPLATE, NULL);
    if (tmplt_in == NULL) {
        std::cerr << "Error: Input template could not be created." << std::endl;
        goto failure;
    }

    if (do_mainloop(trie_map, tmplt_in))
        goto failure;

    thread.join();
    ur_free_template(tmplt_in);
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_FINALIZATION();
	return EXIT_SUCCESS;

failure:
    stop = true;
    thread.join();
    ur_free_template(tmplt_in);
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_FINALIZATION();
    return EXIT_FAILURE;
}
