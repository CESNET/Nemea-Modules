/**
 * @file configuration.cpp
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Implementation of module configuration API
 * @version 1.0
 * @date 16.10.2020
 * 
 * @copyright Copyright (c) 2020 CESNET
 */

#include "configuration.h"
#include "rapidxml.hpp"

#include <fstream>
#include <iostream>
#include <cstring>
#include <string>

#include <unirec/unirec.h>

using namespace rapidxml;

Configuration::Configuration()
{
    _out_tmplt = "TIME_FIRST,TIME_LAST,COUNT";
    _eof_terminate = false;
    _is_biflow_key = false;
    _flow_cache_size = 65536;
    _t_passive = 20;
    _t_active = 40;
}

void Configuration::set_flow_cache_size(const char *input)
{
    _flow_cache_size = 1 << std::stoul(input); 
    if (_flow_cache_size <= 4)
        _flow_cache_size = 4;
}

void Configuration::set_active_timeout(const char *input)
{
    _t_active = std::stoul(input);
}

void Configuration::set_passive_timeout(const char *input)
{
    _t_passive = std::stoul(input);
}

void Configuration::set_eof_termination()
{
    _eof_terminate = true;
}

time_t Configuration::get_passive_timeout() noexcept
{
    return (_t_passive << 32);
}
time_t Configuration::get_active_timeout() noexcept
{
    return (_t_active << 32);
}

std::size_t Configuration::get_flow_cache_size() noexcept
{
    return _flow_cache_size;
}

bool Configuration::get_eof_termination() noexcept
{
    return _eof_terminate;
}

void Configuration::set_global_flush_configuration(const char *input)
{
    std::size_t mode_start_index; 
    _global_flush_configuration.interval = std::stoul(input, &mode_start_index);
    if (std::strcmp(input + mode_start_index, "a") == 0 ||
        std::strcmp(input + mode_start_index, "absolute") == 0) {
        _global_flush_configuration.type = Global_flush_configuration::Type::ABSOLUTE;
    } else if (std::strcmp(input + mode_start_index, "r") == 0 ||
               std::strcmp(input + mode_start_index, "relative") == 0 || 
               std::strcmp(input + mode_start_index, "") == 0) {
        _global_flush_configuration.type = Global_flush_configuration::Type::RELATIVE;
    } else {
        throw std::invalid_argument("Invalid flush timeout format. Expected: <interval> [a|absolute|r|relative|<empty for relative>].");
    } 
}

Configuration::Global_flush_configuration Configuration::get_global_flush_configuration() noexcept
{
    return _global_flush_configuration;
}

void Configuration::print() noexcept
{
    std::cout << "***** Configuration *****" << std::endl;
    std::cout << "Flow cache size: " << _flow_cache_size << std::endl; 
    std::cout << "Active timeout: " << _t_active << std::endl; 
    std::cout << "Passive timeout: " << _t_passive << std::endl; 
    std::cout << "*************************" << std::endl;
}

void Configuration::print_cfg_field(agg::Field_config& field)
{
    std::cout << "----------------" << std::endl;
    std::cout << "Name: " << field.name << std::endl;
    std::cout << "Reverse name: " << field.reverse_name << std::endl;
    std::cout << "Type: " << field.type << std::endl;
    std::cout << "Sort key: " << field.sort_name << std::endl;
    std::cout << "Sort type: " << field.sort_type << std::endl;
    std::cout << "Delimiter: " << field.delimiter << std::endl;
    std::cout << "Size: " << field.limit << std::endl;
    std::cout << "----------------" << std::endl;
}

agg::Field_type Configuration::get_field_type(const char *input)
{
    if (!std::strcmp(input, "KEY")) return agg::KEY;
    if (!std::strcmp(input, "SUM")) return agg::SUM;
    if (!std::strcmp(input, "MIN")) return agg::MIN;
    if (!std::strcmp(input, "MAX")) return agg::MAX;
    if (!std::strcmp(input, "AVG")) return agg::AVG;
    if (!std::strcmp(input, "FIRST")) return agg::FIRST;
    if (!std::strcmp(input, "FIRST_NON_EMPTY")) return agg::FIRST_NON_EMPTY;
    if (!std::strcmp(input, "LAST")) return agg::LAST;
    if (!std::strcmp(input, "LAST_NON_EMPTY")) return agg::LAST_NON_EMPTY;
    if (!std::strcmp(input, "BITAND")) return agg::BIT_AND;
    if (!std::strcmp(input, "BITOR")) return agg::BIT_OR;
    if (!std::strcmp(input, "APPEND")) return agg::APPEND;
    if (!std::strcmp(input, "SORTED_MERGE")) return agg::SORTED_MERGE;
    if (!std::strcmp(input, "SORTED_MERGE_DIR")) return agg::SORTED_MERGE_DIR;
    std::cerr << "Invalid type field. Given: " << input << ", Expected: KEY|SUM|MIN|MAX|AVG|FIRST|FIRST_NON_EMPTY|LAST|LAST_NON_EMPTY|BITAND|BITOR|APPEND|SORTED_MERGE|SORTED_MERGE_DIR." << std::endl;
    return agg::INVALID_TYPE;
}

std::vector<agg::Field_config> Configuration::get_cfg_fields() const noexcept
{
    return _cfg_fields;
}

bool Configuration::is_key_present(std::string key_name)
{
    for (auto cfg_field : _cfg_fields) {
        if (!cfg_field.name.compare(key_name) && cfg_field.type == agg::KEY)
            return true; 
    }
    return false;
}

bool Configuration::verify_field(agg:: Field_config& field)
{
    if (field.type == agg::INVALID_TYPE)
        return false;
    if (field.sort_name.length() == 0 && (field.type == agg::SORTED_MERGE || field.type == agg::SORTED_MERGE_DIR))
        return false;
    if (field.sort_type == agg::INVALID_SORT_TYPE && (field.type == agg::SORTED_MERGE || field.type == agg::SORTED_MERGE_DIR))
        return false;

    // check duplications
    for (auto cfg_field: _cfg_fields) {
        if (field.name.compare(cfg_field.name) == 0) {
            std::cerr << "Duplicit field name (" << field.name <<")" << std::endl;
            return false;
        }
    }

    return true;
}

agg::Sort_type Configuration::get_sort_type(const char *input)
{
    if (!std::strcmp(input, "ASCENDING")) return agg::ASCENDING;
    if (!std::strcmp(input, "DESCENDING")) return agg::DESCENDING;
    std::cerr << "Invalid sort type field. Given: " << input << ", Expected: ASCENDING|DESCENDING." << std::endl;
    return agg::INVALID_SORT_TYPE;
}



std::pair<agg::Field_config, bool> Configuration::parse_field(xml_node<> *xml_field)
{
    agg::Field_config field = {};

    for (xml_node<> *option = xml_field->first_node(); option; option = option->next_sibling()) {
        if (!std::strcmp(option->name(), "name")) {
            field.name = option->value();
        } else if (!std::strcmp(option->name(), "reverse_name")) {
            field.reverse_name = option->value();
        } else if (!std::strcmp(option->name(), "type")) {
            field.type = get_field_type(option->value());
        } else if (!std::strcmp(option->name(), "sort_key")) {
            field.sort_name = option->value();
        } else if (!std::strcmp(option->name(), "sort_type")) {
            field.sort_type = get_sort_type(option->value());
        } else if (!std::strcmp(option->name(), "delimiter")) {
            if (std::strlen(option->value()) != 1) {
                std::cerr << "Invalid delimiter length. Given: " << std::strlen(option->value()) << ", expected: 1." << std::endl;
                return std::make_pair(field, 1);
            }
            field.delimiter = option->value()[0];
        } else if (!std::strcmp(option->name(), "size")) {
            field.limit = std::stoi(option->value(), NULL);
            if (field.limit == 0) {
                std::cerr << "Invalid size format. Given: " << option->value() << ", expected: unsigned number." << std::endl;
                return std::make_pair(field, 1);;
            }
        } else {
            std::cerr << "Invlaid file format. Expected 'name|type|[reverse_name|sort_key|sort_type|delimiter|size]', given '" << option->name() << "'" << std::endl;
            return std::make_pair(field, 1);;
        }
    }
    field.to_output = true;
    //print_cfg_field(field);
    return std::make_pair(field, verify_field(field));
}

int Configuration::check_biflow_key_presence()
{
    const std::vector<std::string> biflow_keys = {"SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "PROTOCOL"};
    int ret = 0;
    
    for (auto key : biflow_keys) {
        if (is_key_present(key) == false) {
            return 0; // not a biflow key
        }
    }

    for (auto field : _cfg_fields) {
        if (!field.name.compare("SRC_IP")) {
            if (field.reverse_name.compare("DST_IP")) {
                std::cerr << "Invalid combination of name/reverse name. Expected SRC_IP/DST_IP" << std::endl;
                ret = 1;
            }
        } else if (!field.name.compare("DST_IP")) {
            if (field.reverse_name.compare("SRC_IP")) {
                std::cerr << "Invalid combination of name/reverse name. Expected DST_IP/SRC_IP" << std::endl;
                ret = 1;
            }
        } else if (!field.name.compare("SRC_PORT")) {
            if (field.reverse_name.compare("DST_PORT")) {
                std::cerr << "Invalid combination of name/reverse name. Expected SRC_PORT/DST_PORT" << std::endl;
                ret = 1;
            }
        } else if (!field.name.compare("DST_PORT")) {
            if (field.reverse_name.compare("SRC_PORT")) {
                std::cerr << "Invalid combination of name/reverse name. Expected DST_PORT/SRC_PORT" << std::endl;
                ret = 1;
            }
        }
    }

    for (auto field : _cfg_fields) {
        if (!field.reverse_name.empty() && is_key_present(field.reverse_name) == false) { // create a reverse field
            agg::Field_config f_cfg = {};
            f_cfg.name = field.reverse_name;
            f_cfg.reverse_name = field.name;
            f_cfg.type = field.type;
            f_cfg.sort_name = field.sort_name;
            f_cfg.sort_type = field.sort_type;
            f_cfg.delimiter = field.delimiter;
            f_cfg.limit = field.limit;
            f_cfg.to_output = false;
            _cfg_fields.emplace_back(f_cfg);
        }
    }

    _is_biflow_key = true;
    return ret;
}

int Configuration::parse_xml(const char *filename, const char *identifier) 
{
    xml_document<> doc;
    std::ifstream file(filename, std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    bool found = false;

    std::vector<char> buffer(size + 1);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Unable to read file " << filename << std::endl;
        return 1;
    }

    doc.parse<0>(buffer.data());
    if (std::strcmp(doc.first_node()->name(), "aggregator")) {
        std::cerr << "Invlaid file format. Expected 'aggregator', given '" << doc.first_node()->name() << "'" << std::endl;
        return 1;
    }

    for (xml_node<> *id = doc.first_node()->first_node(); id; id = id->next_sibling()) {
        if (std::strcmp(id->name(), "id")) {
            std::cerr << "Invlaid file format. Expected 'id', given '" << id->name() << "'" << std::endl;
            return 1;
        }

        rapidxml::xml_attribute<>* attr = id->first_attribute("name");
        if (attr == nullptr) {
            std::cerr << "Invalid file format. Expected '<id name=\"NAME\">'" << std::endl;
            return 1;
        } else {
            if (std::strcmp(attr->value(), identifier))
                continue;
        }

        found = true;

        for (xml_node<> *xml_field = id->first_node(); xml_field; xml_field = xml_field->next_sibling()) {
            if (std::strcmp(xml_field->name(), "field")) {
                std::cerr << "Invalid file format. Expected 'field', given '" << xml_field->name() << "'" << std::endl;
                return 1;
            }
            std::pair<agg::Field_config, bool> p_field = parse_field(xml_field);
            if (p_field.second == false)
                return 1;
            
            _cfg_fields.emplace_back(p_field.first);
        }
        break;
    }

    if (!found) {
        std::cerr << "Invalid file format. No ID (" << identifier << ") found." << std::endl;
        return 1;
    }

    return check_biflow_key_presence();
}

bool Configuration::is_biflow_key() noexcept
{
    return _is_biflow_key;
}