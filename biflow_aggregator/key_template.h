/**
 * @file key_template.h
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Classes that represent flow key.
 * @version 1.0
 * @date 16.10.2020
 * 
 * @copyright Copyright (c) 2020 CESNET
 */

#ifndef KEY_TEMPLATE_H
#define KEY_TEMPLATE_H

#include "xxhash.h"
#include "flat_hash_map.h"

#include <vector>
#include <tuple>
#include <iostream>

#include <unirec/unirec.h>

namespace agg {

/**
 * Class that represent input key fields.
 */
class Key_template {

    /**
     * @brief Vector that store all information about key.
     */
    static std::vector<std::tuple<ur_field_id_t, ur_field_id_t, std::size_t>> _key_fields;

    /**
     * @brief Size of key.
     */
    static std::size_t _key_size;

    friend class FlowKey;

public:
 
    /**
     * @brief Named tuple indexes.
     */
    enum Tuple_name {ID, REVERSE_ID, SIZE};

    /**
     * @brief Add new field to key template.
     * 
     * @param ur_fid    unirec field id
     * @param ur_r_fid  unirec reverse field id
     */
    static void add(ur_field_id_t ur_fid, ur_field_id_t ur_r_fid);

    /**
     * @brief Get key fields
     * 
     * @return std::vector<std::tuple<ur_field_id_t, ur_field_id_t, std::size_t>> 
     */
    static std::vector<std::tuple<ur_field_id_t, ur_field_id_t, std::size_t>> get_fields() noexcept;

    /**
     * @brief Get template key size.
     * 
     * @return std::size_t key template size
     */
    static std::size_t get_size() noexcept;

    /**
     * @brief Reset class to default state.
     */
    static void reset() noexcept;
};

/**
 * Class that store key strings.
 */
struct KeyString {
    std::string str;
    std::size_t cnt;

    KeyString(std::string&& s)
    {
        str = s;
        cnt = 0;
    }
};


/**
 * Class that store key of input flow.
 */
class FlowKey {

    /**
     * @brief Pointer to key data 
     */
    uint8_t *_key_data;

public:

    static ska::flat_hash_map<uint64_t, KeyString> key_strings;

    /**
     * @brief Construct a new Flow Key object
     */
    FlowKey();

    /**
     * @brief Weak copy constructor.
     */
    FlowKey(const FlowKey &other) noexcept;

    /**
     * @brief Move constructor.
     */
    FlowKey(FlowKey &&other) noexcept;

    /**
     * @brief Assign constructor.
     */
    FlowKey& operator=(FlowKey other) noexcept;

    /**
     * @brief Compares two flow keys.
     */
    bool operator==(const FlowKey &other) const noexcept;

    /**
     * @brief Write data from src to key on offset position.
     * 
     * @param src    Pointer to source data 
     * @param size   Size of source data
     * @param offset Offset in destination data.
     */
    void update(const void *src, std::size_t size, std::size_t& offset) noexcept;

    /**
     * @brief Generate key from input flow and template.
     * 
     * @param in_data   Input flow data
     * @param tmplt     Input template
     * @param is_biflow biflow flag
     * @return true     OK
     * @return false    Error
     */
    bool generate(const void *in_data, ur_template_t *tmplt, bool is_biflow);

    /**
     * @brief Get pair of key data that contains pointer to key memory and size of this memory.
     * 
     * @return std::pair<void *, std::size_t> 
     */
    std::pair<void *, std::size_t> get_key() const noexcept;

    void reset();
};

/**
 * @brief Class to allocate Flow key memory
 */
class Flow_key_allocator {

    /**
     * @brief Vector of pointer to key data 
     */
    static std::vector<uint8_t *> _ptrs;

    /**
     * @brief Current index in vector 
     */
    static std::size_t _idx;

    /**
     * @brief Pointer to memory that holds all key data segments 
     */
    static uint8_t *_global;

public:

    /**
     * @brief Init Flow allocator
     * 
     * @param elements Number of elements to reserve
     * @param rec_size Size of key data
     */
    static void init(std::size_t elements, std::size_t rec_size);

    /**
     * @brief Get the pointer to available key data memory
     */
    static uint8_t *get_ptr() noexcept;

    /**
     * @brief Release pointer to key data memory
     */
    static void release_ptr(uint8_t *ptr) noexcept;

    /**
     * @brief Clear and reset allocator to default state.
     */
    static void clear();

    /**
     * @brief Destroy the Flow_key_allocator object
     */
    ~Flow_key_allocator();
};

} // namespace agg

/**
 * XXH3_64bits hash function in std namespace.
 */
namespace std
{
    template<> struct hash<agg::FlowKey>
    {
        std::size_t operator()(agg::FlowKey const& key) const noexcept
        {
            void *data;
            std::size_t size;
            std::tie(data, size) = key.get_key(); 
            return static_cast<std::size_t>(XXH3_64bits(data, size));
        }
    };
}

#endif // KEY_TEMPLATE_H