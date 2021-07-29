/**
 * @file key_template.cpp
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Implementation of classes that represent flow key.
 * @version 1.0
 * @date 16.10.2020
 * 
 * @copyright Copyright (c) 2020 CESNET
 */

#include "key_template.h"
#include "fields.h"

#include <cstring>
#include <iostream>

namespace agg {

// ###############################
// KEY TEMPLATE
// ###############################

constexpr std::size_t string_hash_size = sizeof(uint64_t);

ska::flat_hash_map<uint64_t, KeyString> FlowKey::key_strings;

std::vector<std::tuple<ur_field_id_t, ur_field_id_t, std::size_t>> Key_template::_key_fields;

std::size_t Key_template::_key_size = 0;

void Key_template::add(ur_field_id_t ur_fid, ur_field_id_t r_ur_fid)
{
    if (ur_get_type(ur_fid) == UR_TYPE_STRING) {
        _key_fields.emplace_back(std::make_tuple(ur_fid, r_ur_fid, string_hash_size));
        _key_size += string_hash_size;
        return;
    }
    
    _key_fields.emplace_back(std::make_tuple(ur_fid, r_ur_fid, ur_get_size(ur_fid)));
    _key_size += ur_get_size(ur_fid);
}

void Key_template::reset() noexcept
{
    _key_size = 0;
    _key_fields.clear();
}

std::vector<std::tuple<ur_field_id_t, ur_field_id_t, std::size_t>> Key_template::get_fields() noexcept
{
    return _key_fields;
}

std::size_t Key_template::get_size() noexcept
{
    return _key_size;
}

// ###############################
// FLOW KEY ALLOCATOR
// ###############################

std::size_t Flow_key_allocator::_idx = 0;

uint8_t* Flow_key_allocator::_global = nullptr;

std::vector<uint8_t *> Flow_key_allocator::_ptrs;

void Flow_key_allocator::init(std::size_t elements, std::size_t rec_size)
{
    std::size_t offset = 0;

    clear();

    _ptrs.reserve(elements);
    _global = new uint8_t[rec_size * elements];

    for (std::size_t i = 0; i < elements; i++) {
        _ptrs.emplace_back(&_global[offset]);
        offset += rec_size;
    }
}

uint8_t *Flow_key_allocator::get_ptr() noexcept
{
    return _ptrs[_idx++];
}

void Flow_key_allocator::release_ptr(uint8_t *ptr) noexcept
{
    _ptrs[--_idx] = ptr;
}

void Flow_key_allocator::clear()
{
    delete [] _global;
    _global = nullptr;
    _idx = 0;
    _ptrs.clear();
}

// ###############################
// FLOW KEY
// ###############################

bool FlowKey::generate(const void *in_data, ur_template_t *tmplt, bool is_biflow)
{
    using uint128_t = unsigned __int128;

    // current offset in key data
    std::size_t offset = 0;

    // Allocate key memory if it is necessary
    if (_key_data == nullptr) {
        _key_data = Flow_key_allocator::get_ptr(); 
    }

    // Generate non biflow key
    if (is_biflow == false) {
        for (auto field : Key_template::get_fields()) {
            if (ur_get_type(std::get<Key_template::ID>(field)) == UR_TYPE_STRING) {
                uint64_t hash = XXH3_64bits(ur_get_ptr_by_id(tmplt, in_data, std::get<Key_template::ID>(field)), 
                    ur_get_var_len(tmplt, in_data, std::get<Key_template::ID>(field)));
                update(&hash, std::get<Key_template::SIZE>(field), offset);
            } else {
                update(ur_get_ptr_by_id(tmplt, in_data, std::get<Key_template::ID>(field)), 
                    std::get<Key_template::SIZE>(field), offset);
            }
        }
        return false;
    }

    // Generate biflow key
    if (*reinterpret_cast<uint128_t*>(&ur_get(tmplt, in_data, F_SRC_IP)) 
        > *reinterpret_cast<uint128_t*>(&ur_get(tmplt, in_data, F_DST_IP))) {
        for (auto field : Key_template::get_fields()) {
            update(ur_get_ptr_by_id(tmplt, in_data, std::get<Key_template::REVERSE_ID>(field)), 
                std::get<Key_template::SIZE>(field), offset);
        }
        return true;
    } else {
        for (auto field : Key_template::get_fields()) {
            update(ur_get_ptr_by_id(tmplt, in_data, std::get<Key_template::ID>(field)), 
                std::get<Key_template::SIZE>(field), offset);
        }
        return false;
    }
}

void FlowKey::update(const void *src, std::size_t size, std::size_t& offset) noexcept
{
    std::memcpy(std::addressof(_key_data[offset]), src, size);
    offset += size;
}

std::pair<void *, std::size_t> FlowKey::get_key() const noexcept
{
    return std::make_pair(_key_data, Key_template::_key_size);
}    

FlowKey::FlowKey(const FlowKey &other) noexcept 
    : _key_data(other._key_data) 
{ 

}

FlowKey::FlowKey(FlowKey &&other) noexcept 
    : _key_data(other._key_data) 
{
    other._key_data = nullptr;
}

FlowKey::FlowKey()
{   
    _key_data = nullptr;
}

FlowKey& FlowKey::operator=(FlowKey other) noexcept 
{
    _key_data = other._key_data;
    return *this; 
}

bool FlowKey::operator==(const FlowKey &other) const noexcept
{
    return !std::memcmp(_key_data, other._key_data, Key_template::_key_size);
}

void FlowKey::reset()
{
    if (_key_data)
        Flow_key_allocator::release_ptr(_key_data);
    _key_data = nullptr;
}

} // namespace agg