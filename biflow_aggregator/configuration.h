/**
 * @file configuration.h
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Interface of module configuration
 * @version 1.0
 * @date 16.10.2020
 * 
 * @copyright Copyright (c) 2020 CESNET
 */

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "aggregator.h"
#include "rapidxml.hpp"

#include <string>
#include <vector>

#include <unirec/unirec.h>

/**
 * @brief Class thas holds module configuration
 */
class Configuration {

    /**
     * @brief Configuration of fields from config file.
     */
    std::vector<agg::Field_config> _cfg_fields;

    /**
     * @brief Flow cache size. Maximal number of records in cache.
     * 
     * Must be power of 2
     */ 
    std::size_t _flow_cache_size;

    /**
     * @brief passive timeout
     * 
     * Passive timeout is used in case of record (specified by key) that not 
     * received any update longer then passive timeout. In this case record is 
     * removed from table and send to output interface.
     */
    time_t _t_passive;

    /**
     * @brief active timeout
     * 
     * Active timeout is used in case of record (specified by key) that is 
     * stored in table longer then specified active timeout. In this case 
     * record is removed from table and send to output interface.
     */
    time_t _t_active;

    /**
     * @brief specified key is biflow key. Contains src port, dst port, src ip, dst ip and protocol
     */
    bool _is_biflow_key;

    /**
     * @brief Terminate program when EOF received
     */
    bool _eof_terminate;

    /**
     * @brief Output template in text format 
     */
    std::string _out_tmplt; 

    /**
     * @brief Parse field from xml file
     */
    std::pair<agg::Field_config, bool> parse_field(rapidxml::xml_node<> *xml_field);

    /**
     * @brief Get the sort type of field from text form
     */
    agg::Sort_type get_sort_type(const char *input);

    /**
     * @brief Get the field type of field from text form
     */
    agg::Field_type get_field_type(const char *input);

    /**
     * @brief Verify field configuration
     */
    bool verify_field(agg::Field_config& field);

    /**
     * @brief check if specified key @p key_name is already set.
     * 
     * @param key_name key in text format
     * @return true  key is present
     * @return false key is not present
     */
    bool is_key_present(std::string key_name);

    /**
     * @brief Check if key is biflow
     */
    int check_biflow_key_presence();
    
    /**
     * @brief Print agg::Field_config structure
     * 
     * Debug function 
     */
    void print_cfg_field(agg::Field_config& field);

public:

    /**
     * @brief Construct a new Configuration object
     */
    Configuration();

    /**
     * @brief Get the fields configuration 
     * 
     * @return std::vector<agg::Field_config> 
     */
    std::vector<agg::Field_config> get_cfg_fields() const noexcept;


    /**
     * @brief Parse Xml file
     * 
     * @param filename Path to file
     * @param identifier Unique config identifier
     * @return int 0 OK, 1 error
     */
    int parse_xml(const char *filename, const char *identifier); 

    /**
     * @brief Print command line configuration.
     * 
     * Debug function
     */
    void print() noexcept;

    /**
     * @brief Set the active timeout
     * 
     * See _t_active for more info.
     * 
     * @param input Timeout in text format.
     */
    void set_active_timeout(const char *input);

    /**
     * @brief Get the active timeout object
     */
    time_t get_active_timeout() noexcept;

    /**
     * @brief Set the passive timeout
     * 
     * See _t_passive for more info.
     * 
     * @param input Timeout in text format.
     */
    void set_passive_timeout(const char *input);
    
    /**
     * @brief Get the passive timeout
     */
    time_t get_passive_timeout() noexcept;

    /**
     * @brief Set the eof termination flag.
     */
    void set_eof_termination();

    /**
     * @brief Get the  eof termination flag
     */
    bool get_eof_termination() noexcept;

    /**
     * @brief Set the maximal number of records stored in flow cache.
     * 
     * @param input Size in text format.
     */
    void set_flow_cache_size(const char *input);

    /**
     * @brief Get the flow cache size
     */
    std::size_t get_flow_cache_size() noexcept;

    /**
     * @brief check if key is biflow
     */
    bool is_biflow_key() noexcept;
};

#endif // CONFIGURATION_H