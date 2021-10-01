/**
 * @file agregator.h
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Aggegator interface.
 * @version 0.1
 * @date 31.8.2020
 *   
 * @copyright Copyright (c) 2020 CESNET
 */

#ifndef AGGREGATOR_H
#define AGGREGATOR_H

#include "flat_hash_map.h"
#include "key_template.h"
#include "linked_list.h"

#include <cassert>
#include <string>
#include <vector>
#include <functional>

#include <unirec/unirec.h>

namespace agg {

/**
 * @brief Type of field defining aggregation function.
 */
enum Field_type {
    KEY,
    SUM,
    AVG,
    MIN,
    MAX,
    BIT_AND,
    BIT_OR,
    FIRST,
    FIRST_NON_EMPTY,
    LAST,
    LAST_NON_EMPTY,
    APPEND,
    SORTED_MERGE,
    INVALID_TYPE,
};

/**
 * @brief Type of sort order
 */
enum Sort_type {
    ASCENDING,
    DESCENDING,
    INVALID_SORT_TYPE
};

using uint128_t = unsigned __int128;
using aggr_func = void (*)(const void *, void *);
using post_func = const void *(*)(void *, std::size_t&);
using init_func = void (*)(void *, const void *);
using deinit_func = void (*)(void *);

/**
 * @brief Class that holds field templates information.
 */
class Field_template {
    template<typename T, typename K>
    int assign() noexcept;

    template<typename T>
    int assign_sum() noexcept;

    template<typename T>
    int assign_avg() noexcept;

    template<Field_type ag_type, typename T>
    int assign_bitor_bitand() noexcept;

    template<Field_type ag_type>
    int assign_first_string() noexcept;

    template<Field_type ag_type>
    int assign_last_string() noexcept;

    template<Field_type ag_type, typename T>
    int assign_first() noexcept;

    template<Field_type ag_type, typename T>
    int assign_last() noexcept;

    template<typename T>
    int assign_append() noexcept;

    template<Field_type ag_type, typename T>
    int assign_min_max() noexcept;

protected:

    /**
     * @brief Pointer to aggregation function
     */
    aggr_func ag_fnc;

    /**
     * @brief Pointer to post-processing function
     */
    post_func post_proc_fnc;

    /**
     * @brief Pointer to init function
     */
    init_func init_fnc;

    /**
     * @brief Pointer to deinit function
     */
    deinit_func deinit_fnc;
    
    /**
     * @brief Size of templated type T
     */
    std::size_t typename_size;

    /**
     * @brief Set the templates to field
     * 
     * @param ag_type    Type of aggregation function 
     * @param ur_f_type  Type of unirec field
     */
    int set_templates(const Field_type ag_type, const ur_field_type_t ur_f_type);
    
    /**
     * @brief Set the templates to field
     * 
     * @param ur_f_type          Type of unirec field
     * @param ur_sort_key_f_type Type of KEY unirec field 
     */
    int set_templates(const ur_field_type_t ur_f_type, const ur_field_type_t ur_sort_key_f_type);

public:

    /**
     * @brief Size of memory needed for aggregation of this field.
     */
    std::size_t ag_data_size;
};

/**
 * @brief Structure that holds information about active and passive timeout of flow
 */
struct Timeout_data {

    /**
     * @brief Construct a new Timeout_data object
     * 
     * @param key              Flow key
     * @param passive_timeout  Passive timeout expiration       
     * @param active_timeout   Active timeout expiration
     */
    Timeout_data(FlowKey key, time_t passive_timeout, time_t active_timeout);

    /**
     * @brief Construct a new Timeout_data object
     * 
     */
    Timeout_data() : passive_timeout(0), active_timeout(0)
    {
    }

    FlowKey key;
    time_t passive_timeout;
    time_t active_timeout;
};

/**
 * @brief Structure that holds context of flow data.
 */
struct Context {

    /**
     * @brief Timeout data structure as Linked list item  
     */
    node<Timeout_data> t_data; 

    /**
     * @brief Flow data memory
     * 
     * Variable member length
     */
    uint8_t data[]; 
};

/**
 * @brief 
 */
struct Flow_data {

    /**
     * @brief Construct a new Flow_data object
     */
    Flow_data();

    /**
     * @brief Pointer to flow context structure.
     */
    Context *ctx;

    /**
     * @brief FLow counter
     */
    uint32_t count;

    /**
     * @brief Timestamp of first flow
     */
    time_t time_first;

    /**
     * @brief Timestamp of last flow
     */
    time_t time_last;

    /**
     * @brief Flag that indicates reverse key
     */
    bool reverse;

    /**
     * @brief Update timestamps, reverse flag and counter.
     */
    void update(const time_t first, const time_t last, const uint32_t cnt, bool is_reverse) noexcept;
};

/**
 * @brief Field configuration
 */
struct Field_config {

    /**
     * @brief Field name
     */
    std::string name;

    /**
     * @brief Reverse field name (only for biflow)
     */
    std::string reverse_name;

    /**
     * @brief Field type
     */
    Field_type type;

    /**
     * @brief Sort key name
     */
    std::string sort_name;

    /**
     * @brief Sort key type
     */
    Sort_type sort_type;

    /**
     * @brief Delimiter (only for append and sorted merge)
     */
    char delimiter;

    /**
     * @brief Max size of append and sortd merge data
     */
    std::size_t limit;

    /**
     * @brief Field goes to output template.
     */
    bool to_output;
};

/**
 * @brief Class to represent aggregation field
 */
class Field : public Field_config, public Field_template {
public:

    /**
     * @brief ID of unirec field
     */
    ur_field_id_t ur_fid;

    /**
     * @brief Reverse ID of unirec field
     */
    ur_field_id_t ur_r_fid;

    /**
     * @brief ID of sort key unirec field
     * 
     * only for SORTED_MERGE;
     */
    ur_field_id_t ur_sort_key_id;

    /**
     * @brief Type of unirec sort key field
     * 
     * only for SORTED_MERGE;
     */
    ur_field_type_t ur_sort_key_type;

    /**
     * @brief Construct a new Field object
     * 
     * @param cfg      Field configuration
     * @param ur_fid   Field ID
     * @param ur_r_fid Reverse field ID
     */
    Field(const Field_config cfg, const ur_field_id_t ur_fid, const ur_field_id_t ur_r_fid);

    /**
     * @brief Call field init function.
     */
    void init(void *tmplt_mem, const void *cfg);

    /**
     * @brief Call field aggregation function.
     */
    void aggregate(const void *src, void *dst);

    /**
     * @brief Call field deinitialization
     */
    void deinit(void *src);

    /**
     * @brief Call field post-processing function.
     */
    const void *post_processing(void *ag_data, std::size_t& typename_size, std::size_t& elem_cnt);
};

/**
 * @brief Class to represent all aggregation fields and memory that fields need 
 */
class Fields {
    
    /**
     * @brief Current offster to memory that holds fields
     */
    std::size_t _offset;

    /**
     * @brief vector of all fields and their sizes
     */
    std::vector<std::pair<Field, std::size_t>> _fields;

public:

    /**
     * @brief Construct a new Fields object
     */
    Fields() : _offset(0)
    {
    }

    /**
     * @brief Get the size of all fields
     */
    std::size_t get_size() noexcept;

    /**
     * @brief Add field
     */
    void add_field(Field &field);
    
    /**
     * @brief Reset to default state
     */
    void reset() noexcept;

    /**
     * @brief Init field memory
     * 
     * @param memory Pointer to field memory
     */
    void init(uint8_t *memory);

    /**
     * @brief DeInit field memory
     * 
     * @param memory Pointer to field memory
     */
    void deinit(uint8_t *memory);

    /**
     * @brief return vector of all fields and their size
     */
    std::vector<std::pair<Field, std::size_t>> get_fields() noexcept;
};


// TODO reinit after release
/**
 * @brief Class to allocate Context of flow data
 */
class Flow_data_context_allocator {
    
    /**
     * @brief Vector of allocated pointers 
     */
    static std::vector<Context *> _ptrs;

    /**
     * @brief Current index to vector 
     */
    static std::size_t _idx;

    /**
     * @brief Pointer to memory that holds all Context structures.
     */
    static uint8_t *_global;

    /**
     * @brief Pointer to function that initialize flow field data
     */
    static std::function<void(uint8_t *)> _init_field;

    /**
     * @brief Pointer to function that deinitialize flow field data
     */
    static std::function<void(uint8_t *)> _deinit_field;

public:

    /**
     * @brief Init allocator
     * 
     * @param elements Number of elements to reserve
     * @param rec_size Size of flow data
     * @param init_field Pointer to function that init flow data.
     */
    static void init(std::size_t elements, std::size_t data_size, std::function<void(uint8_t *)> init_field, std::function<void(uint8_t *)> deinit_field);

    /**
     * @brief Get the pointer to available Context memory
     */
    static Context *get_ptr() noexcept;

    /**
     * @brief  Release pointer to Context memory
     */
    static void release_ptr(Context *ptr) noexcept;

    /**
     * @brief Clear and reset allocator to default state.
     */
    static void clear();

    /**
     * @brief Deinitialize all memory
     */
    static void deinit();

    /**
     * @brief Destroy the Flow_key_allocator object
     * 
     */
    ~Flow_data_context_allocator();
};

/**
 * @brief Aggregator class, holds all aggregation fields and flow cache
 * 
 * @tparam Key Type of Flow key
 */
template<typename Key>
class Aggregator {

public:

    Fields fields;

    /**
     * @brief Construct a new Aggregator object
     * 
     * Reserve flow cache size
     * 
     * @param flow_cache_size Maximal flow cache size, power of 2
     */
    Aggregator(std::size_t flow_cache_size)
    {
        flow_cache.reserve(flow_cache_size);
    }

    /**
     * @brief Flow cache, holds keys and data
     */
    ska::flat_hash_map<Key, Flow_data> flow_cache;
};

} // namespace agg

#endif // AGGREGATOR_H    
