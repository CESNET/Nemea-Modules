/**
 * @file main.cpp
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Bi-flow aggregator
 * @version 1.0
 * @date 16.10.2020
 * 
 * @copyright Copyright (c) 2020 CESNET
 */

#include "configuration.h"
#include "key_template.h"
#include "aggregator.h"
#include "aggregator_functions.h"
#include "flat_hash_map.h"
#include "fields.h"

#include <iostream>
#include <csignal>
#include <cstring>
#include <thread>

#include <getopt.h>
#include <unistd.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x),0)

/**
 * Statically defined fields COUNT, TIME_FIRST, TIME_LAST, SRC_IP and DST_IP always used by module
 */
UR_FIELDS ( 
    time TIME_FIRST,
    time TIME_LAST,
    uint32 COUNT,
    ipaddr SRC_IP,
    ipaddr DST_IP
)

/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
    BASIC("aggregator", \
        "The module can aggregate UniRec records based on user-specified keys, aggregation functions and time interval. " \
        "The input of this module is a (infinit) sequence of UniRec records. The output of this module is a " \
        "sequence of aggregated UniRec records according to user settings.\n\n" \
        "User has to specify parameters for processing including key fields and applied aggregation function. " \
        "User can specify aggregation functions by options listed below, all options may be used repeatedly. " \
        "URFIELD stands for name of the UniRec field.\n\n" \
        "Module can work with 2 different timeout types (Active and Passive) or their combination " \
        "(Mixed = Active,Passive)." \
        "Module receives UniRec and sends UniRec containing the fields which take part in aggregation process.\n\n" \
        "Module use in place aggregation, so only one aggregation function per field is possible. " \
        "Only fields specified by user are part of output record, others are discarded. " \
        "Please notice the field COUNT (count of aggregated records) is always inside output record.\n\n" \
        "Example:\n Records aggregated by SRC_IP and DST_IP, " \
        "making sum of BYTES and PACKETS and using first received value of SRC_PORT in output. " \
        "Module can be run like this:\n" \
        "  " BINDIR "/aggregator -i u:input,u:aggr -c config.xml\n", \
         1, 1)


/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 */
#define MODULE_PARAMS(PARAM) \
    PARAM('c', "config", "Configuration file in xml format.", required_argument, "filename") \
    PARAM('n', "name", "Name of config section.", required_argument, "name") \
    PARAM('e', "eof", "End when receive EOF.", no_argument, "flag") \
    PARAM('s', "size", "Max number of elements in flow cache.", required_argument, "number") \
    PARAM('a', "active-timeout", "Active timeout.", required_argument, "number") \
    PARAM('p', "passive-timeout", "Passive timeout.", required_argument, "number") \
    PARAM('g', "global-timeout", "Global timeout.", required_argument, "number")

trap_module_info_t *module_info = NULL;
static volatile int stop = 0;
static volatile bool force_stop = true;

/**
 * @brief Kill program
 */
void kill_self_timer(int time)
{
    sleep(time);
    if (force_stop == true) {
        kill(getpid(), SIGINT);
    }
}

/**
 * Function to handle SIGTERM and SIGINT signals used to stop the module.
 * @param [in] signal caught signal value.
 */
static void
termination_handler(const int signum) 
{
    if (signum == SIGINT) {
        std::cerr << "Signal " << signum << " caught, exiting module." << std::endl;
        signal(SIGINT, SIG_DFL);
        std::thread t1(kill_self_timer, 3);
        t1.detach();
        stop = 1;
    }
}


/**
 * Install signal handlee to SIGTERM and SIGINT signals.
 * @param [in] signal caught signal value.
 */
static int
install_signal_handler(struct sigaction &sigbreak)
{
    static const int signum[] = {SIGINT, SIGTERM};

    sigbreak.sa_handler = termination_handler;
    sigemptyset(&sigbreak.sa_mask);
    sigbreak.sa_flags = 0;

    for (int i = 0; signum[i] != SIGTERM; i++) {
        if (sigaction(signum[i], &sigbreak, NULL) != 0) {
            std::cerr << "sigaction() error." << std::endl;
            return 1;
        }
    }
    return 0;
}

/**
 * Send record to output interface.
 * @param [in] out_tmplt UniRec template of output record.
 * @param [in] out_rec pointer to record which is going to be send
 * @return True if record successfully sent, false if record was not send.
 */
static bool 
send_record_out(ur_template_t *out_tmplt, void *out_rec)
{
    constexpr int max_try = 3;
    int ret;

    for (int i = 0; i < max_try; i++) {
        ret = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));
        TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
        return true;
    }
    std::cerr << "Cannot send record due to error or time_out" << std::endl;
    return false;
}


static void 
proccess_and_send(agg::Aggregator<agg::FlowKey>& agg, const agg::FlowKey& key, const agg::Flow_data& flow_data, ur_template_t *out_tmplt, void *out_rec) 
{
    ur_field_id_t field_id;
    agg::Field *field;
    std::size_t offset = 0;
    std::size_t elem_cnt;
    std::size_t size;
    void *key_data;

    std::tie(key_data, std::ignore) = key.get_key();

    // set mandatory fileds
    ur_set(out_tmplt, out_rec, F_TIME_FIRST, flow_data.time_first);
    ur_set(out_tmplt, out_rec, F_TIME_LAST, flow_data.time_last);
    ur_set(out_tmplt, out_rec, F_COUNT, flow_data.count);

    // Add key fields
    for (auto tmplt_field : agg::Key_template::get_fields()) {  
        field_id = flow_data.reverse ? std::get<agg::Key_template::REVERSE_ID>(tmplt_field) : std::get<agg::Key_template::ID>(tmplt_field);
        if (ur_get_type(field_id) == UR_TYPE_STRING) {
            auto data = agg::FlowKey::key_strings.find(*((uint64_t *)(&static_cast<char *>(key_data)[offset])));
            ur_set_string(out_tmplt, out_rec, field_id, data->second.str.c_str());
            if (--(data->second.cnt) == 0)
                agg::FlowKey::key_strings.erase(data->first);
        } else
            std::memcpy(ur_get_ptr_by_id(out_tmplt, out_rec, field_id), std::addressof(static_cast<char *>(key_data)[offset]), ur_get_size(std::get<agg::Key_template::REVERSE_ID>(tmplt_field)));
        offset += std::get<agg::Key_template::SIZE>(tmplt_field);
    }

    // Add aggregated fields
    for (auto agg_field : agg.fields.get_fields()) {
        field = std::addressof(agg_field.first);
        const void *agg_data;
        if (field->type == agg::SORTED_MERGE_DIR) {
            agg_data = field->post_processing_sm_dir(&flow_data.ctx->data[agg_field.second], size, elem_cnt, flow_data.reverse);
        } else {
            agg_data = field->post_processing(&flow_data.ctx->data[agg_field.second], size, elem_cnt);
        }
        if (ur_is_array(field->ur_fid)) {
            ur_array_allocate(out_tmplt, out_rec, field->ur_fid, elem_cnt);
            std::memcpy(ur_get_ptr_by_id(out_tmplt, out_rec, field->ur_fid), agg_data, size * elem_cnt);
        } else {
            field_id = flow_data.reverse ? field->ur_r_fid : field->ur_fid;
            std::memcpy(ur_get_ptr_by_id(out_tmplt, out_rec, field_id), agg_data, size);
        }
    }
    (void) send_record_out(out_tmplt, out_rec);
}

static int process_format_change(
        Configuration& config,
        agg::Aggregator<agg::FlowKey>& agg,
        ur_template_t *in_tmplt,
        ur_template_t **out_tmplt,
        bool& is_string_key
        )
{
    ur_field_id_t ur_fid;
    ur_field_id_t ur_r_fid;

    std::string out_template = "TIME_FIRST,TIME_LAST,COUNT";

    /*
     * Iterate over all fields specified in configuration and check if input template contains these fields.
     */
    for (auto field_cfg : config.get_cfg_fields()) {
        ur_fid = ur_get_id_by_name(field_cfg.name.c_str());
        ur_r_fid = ur_get_id_by_name(field_cfg.reverse_name.c_str());

        if (!ur_is_present(in_tmplt, ur_fid)) {
            std::cerr << "Requested field " << field_cfg.name << " is not in input records, cannot continue." << std::endl;
            return 1;
        }

        if (ur_r_fid != UR_E_INVALID_NAME && !ur_is_present(in_tmplt, ur_r_fid)) {
            std::cerr << "Requested field " << field_cfg.reverse_name << " is not in input records, cannot continue." << std::endl;
            return 1;
        } else if (ur_r_fid == UR_E_INVALID_NAME) {
            ur_r_fid = ur_fid;
        } else {
            if (ur_get_size(ur_fid) != ur_get_size(ur_r_fid)) {
                std::cerr << "Name and reverse name field size is not equal, cannot continue." << std::endl;
                return 1;
            }
        }

         if (field_cfg.type == agg::KEY) {
            if (ur_get_type(ur_fid) == UR_TYPE_STRING)
                is_string_key = true;
            agg::Key_template::add(ur_fid, ur_r_fid);
        } else {
            agg::Field field(field_cfg, ur_fid, ur_r_fid);
            agg.fields.add_field(field);
        }
        if (field_cfg.to_output)
            out_template.append("," + field_cfg.name);
    }

    *out_tmplt = ur_create_output_template(0, out_template.c_str(), NULL);
    if (*out_tmplt == NULL) {
        std::cerr << "Error: Output template could not be created." << std::endl;
        return 1;
    }

    return 0;
}

/**
 * @brief Process strings in key.
 *
 * Store new string to map.
 */
static void 
process_key_string(const agg::FlowKey& key, const void *in_data, ur_template_t *in_tmplt)
{
    std::size_t offset = 0;
    void *key_data;
    std::string str;
    std::tie(key_data, std::ignore) = key.get_key();
    for (auto tmplt_field : agg::Key_template::get_fields()) {  
        ur_field_id_t field_id = std::get<agg::Key_template::ID>(tmplt_field);
        if (ur_get_type(field_id) == UR_TYPE_STRING) {
            str.assign(static_cast<const char *>(ur_get_ptr_by_id(in_tmplt, in_data, field_id)), ur_get_var_len(in_tmplt, in_data, field_id));
            agg::KeyString key_string(std::move(str));
            auto data = agg::FlowKey::key_strings.insert(*reinterpret_cast<uint64_t *>(&static_cast<char *>(key_data)[offset]), key_string);
            data.first->second.cnt++;
        }
        offset += std::get<agg::Key_template::SIZE>(tmplt_field);
    }
}

void post_insert_flow(
    const void *in_data,
    ur_template_t *in_tmplt,
    agg::FlowKey& key, 
    agg::Flow_data& flow_data,
    Dll<agg::Timeout_data>& dll,
    bool is_string_key, 
    bool is_key_reversed,
    time_t time_first,
    time_t time_last, 
    time_t t_passive, 
    time_t t_active)
{
    agg::Context *ctx = agg::Flow_data_context_allocator::get_ptr();
    agg::Timeout_data timeout_data(key, time_last + t_passive, time_first + t_active);
    ctx->t_data.init(std::move(timeout_data));
    flow_data.ctx = ctx;

    flow_data.update(ur_get(in_tmplt, in_data, F_TIME_FIRST), 
                     ur_get(in_tmplt, in_data, F_TIME_LAST),
                     ur_is_present(in_tmplt, F_COUNT) ? ur_get(in_tmplt, in_data, F_COUNT) : 1,
                     is_key_reversed);

    dll.insert(&ctx->t_data);
    if (is_string_key)
        process_key_string(key, in_data, in_tmplt);
}

void pre_delete_flow(
    void *out_rec,
    ur_template_t *out_tmplt,
    agg::Aggregator<agg::FlowKey>& agg,
    agg::FlowKey& key, 
    agg::Flow_data& flow_data,
    Dll<agg::Timeout_data>& dll)
{
    node<agg::Timeout_data> *t_data = &flow_data.ctx->t_data;
    proccess_and_send(agg, key, flow_data, out_tmplt, out_rec);
    agg::Flow_data_context_allocator::release_ptr(flow_data.ctx); 
    agg::Flow_key_allocator::release_ptr(static_cast<uint8_t *>(key.get_key().first));
    dll.delete_node(t_data);
}

void update_flow(
    const void *in_data,
    ur_template_t *in_tmplt,
    agg::FlowKey& key, 
    agg::Flow_data& flow_data,
    Dll<agg::Timeout_data>& dll,
    bool is_key_reversed,
    time_t t_passive, 
    time_t t_active)
{
    time_t time_last;
    time_t time_first;
    time_t pt;

    node<agg::Timeout_data> *t_data = &flow_data.ctx->t_data;
    flow_data.update(ur_get(in_tmplt, in_data, F_TIME_FIRST), 
                     ur_get(in_tmplt, in_data, F_TIME_LAST),
                     ur_is_present(in_tmplt, F_COUNT) ? ur_get(in_tmplt, in_data, F_COUNT) : 1,
                     is_key_reversed);

    time_last  = ur_time_get_sec(flow_data.time_last);
    time_first = ur_time_get_sec(flow_data.time_first);
    pt = t_data->value.passive_timeout;
    if (time_first + t_active < t_data->value.active_timeout)
        t_data->value.active_timeout = time_first + t_active;
    if (time_last + t_passive < t_data->value.active_timeout)
        t_data->value.passive_timeout = time_last + t_passive;
    else
        t_data->value.passive_timeout = t_data->value.active_timeout;
    if (pt != t_data->value.passive_timeout)
        dll.swap(t_data);
}

static void flush_all(agg::Aggregator<agg::FlowKey>& aggregator, 
    ur_template_t* out_template, void* out_record, Dll<agg::Timeout_data>& dll) 
{
    for (auto flow_data : aggregator.flow_cache) {
        proccess_and_send(aggregator, flow_data.first, flow_data.second, out_template, out_record);
        agg::Flow_key_allocator::release_ptr(static_cast<uint8_t *>(flow_data.first.get_key().first));
        agg::Flow_data_context_allocator::release_ptr(flow_data.second.ctx);        
    }
    dll.clear();
    aggregator.flow_cache.clear();
    trap_send_flush(0);
}

static int 
do_mainloop(Configuration& config)
{
    agg::Aggregator<agg::FlowKey> agg(config.get_flow_cache_size());
    ur_template_t *in_tmplt;
    ur_template_t *out_tmplt = NULL;
    uint16_t flow_size;
    const void *in_data;
    void *out_rec = NULL;
    int recv_code;
    agg::FlowKey key;
    agg::Flow_data placeholder;
    std::pair<agg::FlowKey, agg::Flow_data> removed;
    agg::Field *field;
    bool is_string_key = false;
    bool timeouted = false;

    time_t time_first;
    time_t time_last = 0;
    time_t last_flush_time = 0;
    time_t t_passive = config.get_passive_timeout() >> 32;
    time_t t_active = config.get_active_timeout() >> 32;
    const Configuration::Global_flush_configuration& flush_configuration 
        = config.get_global_flush_configuration();
    std::size_t flow_cnt = 0;
    Dll<agg::Timeout_data> dll;

    trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, 500000);
    //trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, 1);

    //  Create UniRec input templates
    in_tmplt = ur_create_input_template(0, "TIME_FIRST,TIME_LAST", NULL);
    if (in_tmplt == NULL) {
        std::cerr << "Error: Input template could not be created." << std::endl;
        return 1;
    }

    while (unlikely(stop == false)) {

    	// Check timeouted flows
        for (node<agg::Timeout_data> *t_data = dll.begin(); !flush_configuration.is_set() && t_data != NULL; t_data = t_data->next) {
            if (time_last >= t_data->value.passive_timeout) { // timeouted 
                auto data = agg.flow_cache.find(t_data->value.key);
                proccess_and_send(agg, data->first, data->second, out_tmplt, out_rec);
                agg::Flow_data_context_allocator::release_ptr(data->second.ctx); 
                agg::Flow_key_allocator::release_ptr(static_cast<uint8_t *>(data->first.get_key().first));
                agg.flow_cache.erase(data);
                dll.delete_first_node();
                timeouted = true;
            } else
                break;
        }
        if (timeouted == true) {
            trap_send_flush(0);
            timeouted = false;
        }

        recv_code = TRAP_RECEIVE(0, in_data, flow_size, in_tmplt);
        TRAP_DEFAULT_RECV_ERROR_HANDLING(recv_code, continue, break);
        if (unlikely(flow_size <= 1)) {
            if (config.get_eof_termination()) {
                stop = 1;
                break;
            } else
                continue;
        }

        if (unlikely(TRAP_E_FORMAT_CHANGED == recv_code)) {

            // clear all memory
            // flush all flows
            flush_all(agg, out_tmplt, out_rec, dll);

            // Free previous record and temlate
            ur_free_template(out_tmplt);
            ur_free_record(out_rec);

            key.reset();
            agg.fields.reset();
            agg.flow_cache.clear();
            agg::Key_template::reset();
            dll.clear();

            if (process_format_change(config, agg, in_tmplt, std::addressof(out_tmplt), is_string_key) != 0) {
                stop = 1;
                break;
            }
            out_rec = ur_create_record(out_tmplt, UR_MAX_SIZE);
            if (out_rec == NULL) {
                std::cerr << "Error: Output record could not be created." << std::endl;
                stop = 1;
                break;
            }

            agg::Flow_key_allocator::init(config.get_flow_cache_size() + 1, agg::Key_template::get_size());
            agg::Flow_data_context_allocator::init(
                config.get_flow_cache_size() + 1, 
                agg.fields.get_size(), 
                std::bind(&agg::Fields::init, agg.fields, std::placeholders::_1),
                std::bind(&agg::Fields::deinit, agg.fields, std::placeholders::_1));
        }

        time_first = ur_time_get_sec(ur_get(in_tmplt, in_data, F_TIME_FIRST));
        if (time_last < ur_time_get_sec(ur_get(in_tmplt, in_data, F_TIME_LAST)))
            time_last = ur_time_get_sec(ur_get(in_tmplt, in_data, F_TIME_LAST));

        // Check timeouted flows
        for (node<agg::Timeout_data> *t_data = dll.begin(); !flush_configuration.is_set() && t_data != NULL; t_data = t_data->next) {
            if (time_first >= t_data->value.passive_timeout || time_last >= t_data->value.active_timeout) { // timeouted 
                auto data = agg.flow_cache.find(t_data->value.key);
                proccess_and_send(agg, data->first, data->second, out_tmplt, out_rec);
                agg::Flow_data_context_allocator::release_ptr(data->second.ctx); 
                agg::Flow_key_allocator::release_ptr(static_cast<uint8_t *>(data->first.get_key().first));
                agg.flow_cache.erase(data);
                dll.delete_first_node();
                timeouted = true;
            } else
                break;
        }
        if (timeouted == true) {
            trap_send_flush(0);
            timeouted = false;
        }

        if (unlikely(flush_configuration.is_set() && time_last - last_flush_time >= flush_configuration.interval)) {
            last_flush_time = time_last;
            if (flush_configuration.type == Configuration::Global_flush_configuration::Type::ABSOLUTE) {
                last_flush_time = last_flush_time / flush_configuration.interval * flush_configuration.interval;
            }    
            flush_all(agg, out_tmplt, out_rec, dll);
        }
        
        bool is_key_reversed = key.generate(in_data, in_tmplt, config.is_biflow_key());

        auto insered_data = agg.flow_cache.insert_no_grow(removed, std::move(key), placeholder); // todo insert only key
        switch (insered_data.second) {
        case ska::DUPLICATED:
            update_flow(in_data,
                        in_tmplt,
                        insered_data.first->first,
                        insered_data.first->second,
                        dll,
                        is_key_reversed,
                        t_passive,
                        t_active);
        	break;
        case ska::INSERTED:
        	post_insert_flow(in_data,
                             in_tmplt,
                             insered_data.first->first,
                             insered_data.first->second,
                             dll,
                             is_string_key,
                             is_key_reversed,
                             time_first,
                             ur_time_get_sec(ur_get(in_tmplt, in_data, F_TIME_LAST)),
                             t_passive,
                             t_active);
            break;
        case ska::SWAPPED:
            pre_delete_flow(out_rec,
                            out_tmplt,
                            agg,
                            removed.first,
                            removed.second,
                            dll);
            post_insert_flow(in_data,
                             in_tmplt,
                             insered_data.first->first,
                             insered_data.first->second,
                             dll,
                             is_string_key,
                             is_key_reversed,
                             time_first,
                             ur_time_get_sec(ur_get(in_tmplt, in_data, F_TIME_LAST)),
                             t_passive,
                             t_active);
            break;
        case ska::FULL: {
            auto to_delete = agg.flow_cache.get_delete_candidate(std::move(key));
            pre_delete_flow(out_rec,
                            out_tmplt,
                            agg,
                            to_delete->first, 
                            to_delete->second,
                            dll);
            agg.flow_cache.erase(to_delete->first);
            insered_data = agg.flow_cache.insert_no_grow(removed, std::move(key), placeholder); // cant fail
            post_insert_flow(in_data,
                             in_tmplt,
                             insered_data.first->first,
                             insered_data.first->second,
                             dll,
                             is_string_key,
                             is_key_reversed,
                             time_first,
                             ur_time_get_sec(ur_get(in_tmplt, in_data, F_TIME_LAST)),
                             t_passive,
                             t_active);
            break;
        }
        default:
            throw std::runtime_error("Invalid case option (flat_hash_map).");
            break;
        }

        agg::Flow_data *cache_data = static_cast<agg::Flow_data *>(std::addressof(insered_data.first->second));
        for (auto agg_field : agg.fields.get_fields()) {
            field = std::addressof(agg_field.first);
            if (ur_is_array(field->ur_fid)) {
                if (field->type == agg::SORTED_MERGE_DIR) {
                    agg::ur_array_dir_data src_dir_data;
                    src_dir_data.cnt_elements = ur_array_get_elem_cnt(in_tmplt, in_data, field->ur_fid);
                    src_dir_data.ptr_first = ur_get_ptr_by_id(in_tmplt, in_data, field->ur_fid);
                    src_dir_data.sort_key = ur_get_ptr_by_id(in_tmplt, in_data, field->ur_sort_key_id);
                    if (ur_is_array(field->ur_sort_key_id))
                        src_dir_data.sort_key_elements = ur_array_get_elem_cnt(in_tmplt, in_data, field->ur_sort_key_id);
                    else
                        src_dir_data.sort_key_elements = 1;
                    src_dir_data.is_key_reversed = is_key_reversed;
                    field->aggregate(std::addressof(src_dir_data), std::addressof(cache_data->ctx->data[agg_field.second]));
                } else {
                    agg::ur_array_data src_data;
                    src_data.cnt_elements = ur_array_get_elem_cnt(in_tmplt, in_data, field->ur_fid);
                    src_data.ptr_first = ur_get_ptr_by_id(in_tmplt, in_data, field->ur_fid);
                    if (field->type == agg::SORTED_MERGE) {
                        src_data.sort_key = ur_get_ptr_by_id(in_tmplt, in_data, field->ur_sort_key_id);
                        if (ur_is_array(field->ur_sort_key_id))
                            src_data.sort_key_elements = ur_array_get_elem_cnt(in_tmplt, in_data, field->ur_sort_key_id);
                        else
                            src_data.sort_key_elements = 1;

                    }
                    field->aggregate(std::addressof(src_data), std::addressof(cache_data->ctx->data[agg_field.second]));
                }
            } else {
                ur_field_id_t field_id = is_key_reversed ? field->ur_r_fid : field->ur_fid;
                field->aggregate(ur_get_ptr_by_id(in_tmplt, in_data, field_id), std::addressof(cache_data->ctx->data[agg_field.second]));
            }
        }

        flow_cnt++;
    }

    for (auto flow_data : agg.flow_cache) {
        proccess_and_send(agg, flow_data.first, flow_data.second, out_tmplt, out_rec);
        agg::Flow_key_allocator::release_ptr(static_cast<uint8_t *>(flow_data.first.get_key().first));
        agg::Flow_data_context_allocator::release_ptr(flow_data.second.ctx);
    }

    //send eof
    char dummy[1] = {0};
    trap_send(0, dummy, 1);
    trap_send_flush(0);

    force_stop = false;

    agg::Flow_key_allocator::clear();
    agg::Flow_data_context_allocator::deinit();
    ur_free_record(out_rec);
    ur_free_template(in_tmplt);
    ur_free_template(out_tmplt);
    return 0;
}

int
main(int argc, char **argv)
{
    struct sigaction sigbreak;
    char *cfg_name = nullptr;
    char *cfg_path = nullptr;
    Configuration config;
    char opt;

    // Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO.
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

    // Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

    // Install SIGINT and SIGTERN signal handler. 
    install_signal_handler(sigbreak);

    while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
        case 'a':
            config.set_active_timeout(optarg);
            break;
        case 'p':
            config.set_passive_timeout(optarg);
            break;
        case 'n':
            cfg_name = optarg;
            break;
        case 'c':
            cfg_path = optarg;
            break;
        case 'e':
            config.set_eof_termination();
            break;
        case 's':
            config.set_flow_cache_size(optarg);
            break;
        case 'g':
            config.set_global_flush_configuration(optarg);
            break;
        default:
            std::cerr << "Invalid argument " << opt << ", skipped..." << std::endl;
        }
    }

    //config.print();

    if (!cfg_path || !cfg_name) {
        std::cerr << "Config filename or config section missing." << std::endl;
        goto failure;
    }

    try {
        if (config.parse_xml(cfg_path, cfg_name) != 0)
           goto failure;
    } catch (rapidxml::parse_error &e) {
        goto failure;
    }
    if (config.get_passive_timeout() > config.get_active_timeout()) {
        std::cerr << "Passive timeout cannot be bigger than active timeout." << std::endl;
        goto failure;
    }

    try {
        if (do_mainloop(config) != 0)
            goto failure;
    } catch ( std::runtime_error &e) {
      std::cerr << e.what() << std::endl;
      goto failure;
    }
    trap_terminate();
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_FINALIZATION();
    return 0;

failure:
    trap_terminate();
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_FINALIZATION();
    return 1;
}
