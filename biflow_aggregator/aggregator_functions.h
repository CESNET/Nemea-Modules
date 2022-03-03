/**
 * @file agregator_functions.h
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Templated aggregation functions.
 * @version 0.1
 * @date 31.8.2020
 *   
 * @copyright Copyright (c) 2020 CESNET
 */

#ifndef AGGREGATOR_FUNCTIONS_H
#define AGGREGATOR_FUNCTIONS_H

#include "aggregator.h"

#include <iostream>
#include <limits>

#include <unirec/unirec.h>

namespace agg {

/**
 * @brief Structure of unirec array input.
 */
struct ur_array_data {
    std::size_t cnt_elements;
    const void *ptr_first;
    const void *sort_key;
    std::size_t sort_key_elements;
};

/**
 * @brief Structure of unirec array input.
 */
struct ur_array_dir_data {
    std::size_t cnt_elements;
    const void *ptr_first;
    const void *sort_key;
    std::size_t sort_key_elements;
    bool is_key_reversed;
};

/** 
 * @brief Basic template data structure that store variable of given type T.
 */ 
template <typename T>
struct Basic_data {
    T data; 

    static inline void init(void *mem, const void *cfg) noexcept
    {
        Basic_data<T> *basic = new(mem) Basic_data<T>();
        if (cfg != nullptr)
            basic->data = std::numeric_limits<T>::max();
    }

    static inline void deinit(void *mem)
    {
        Basic_data<T> *basic = static_cast<Basic_data<T> *>(mem);
        basic->~Basic_data<T>();
    }
};

/**
 * @brief Structure used to store data for average function.
 */
template <typename T>
struct Average_data : Basic_data<T> {
    uint32_t cnt;

    static inline void init(void *mem, const void *cfg) noexcept
    {
        (void) cfg;
        new(mem) Average_data<T>();
    }

    static inline void deinit(void *mem)
    {
        Average_data<T> *avg = static_cast<Average_data<T> *>(mem);
        avg->~Average_data<T>();
    }

    static inline const void *postprocessing(void *mem, std::size_t& elem_cnt) noexcept
    {
        Average_data<T> *avg = static_cast<Average_data<T>*>(mem);
        avg->data /= avg->cnt;
        return static_cast<void *>(&avg->data);
    }
};

/**
 * @brief Structure used to store data for function that needs hold init flag.
 */
template <typename T>
struct First_init_data : Basic_data<T> {
    bool is_set;

    static inline void init(void *mem, const void *cfg) noexcept
    {
        (void) cfg;
        new(mem) First_init_data<T>();
    }

    static inline void deinit(void *mem)
    {
        First_init_data<T> *first = static_cast<First_init_data<T> *>(mem);
        first->~First_init_data<T>();
    }
};

/**
 * @brief Structure used to store data for function that needs hold init flag.
 */
struct String_data {
    std::string data;
    bool is_set;

    static inline void init(void *mem, const void *cfg)
    {
        (void) cfg;
        new(mem) String_data();
    }

    static inline void deinit(void *mem)
    {
        String_data *s_data = static_cast<String_data*>(mem);
        s_data->~String_data();
    }

    static inline const void *postprocessing(void *mem, std::size_t& elem_cnt) noexcept
    {
        String_data *s_data = static_cast<String_data*>(mem);
        elem_cnt = s_data->data.size(); 
        return s_data->data.data();
    }
};

/**
 * @brief Configuration to append function 
 */
struct Config_append {
    std::size_t limit;
    char delimiter;
};

/**
 * @brief Structure used to store data for append function.
 */
template<typename T>
struct Append_data : Config_append {
    std::vector<T> data;
    
    static inline void init(void *mem, const void *cfg)
    {
        Append_data<T> *append = new(mem) Append_data<T>();
        const Config_append *config = static_cast<const Config_append *>(cfg);
        append->limit = config->limit;
        append->delimiter = config->delimiter;
        append->data.reserve(config->limit);
    }

    static inline void deinit(void *mem)
    {
        Append_data<T> *append = static_cast<Append_data<T>*>(mem);
        append->~Append_data<T>();
    }

    static inline const void *postprocessing(void *mem, std::size_t& elem_cnt) noexcept
    {
        Append_data<T> *append = static_cast<Append_data<T>*>(mem);
        elem_cnt = append->data.size(); 
        return append->data.data();
    }
};

/**
 * @brief Configuration to sorted merge function
 */
struct Config_sorted_merge {
    std::size_t limit;
    char delimiter;
    Sort_type sort_type;
};

/**
 * @brief Structure used to store data for sorted append function.
 */
template <typename T, typename K>
struct Sorted_merge_data : Config_sorted_merge {
    std::vector<std::pair<T, K>> data;
    std::vector<T> result;
    
    static inline void init(void *mem, const void *cfg)
    {
        Sorted_merge_data<T, K> *sorted_merge = new(mem) Sorted_merge_data<T, K>();
        const Config_sorted_merge *config = static_cast<const Config_sorted_merge *>(cfg);
        sorted_merge->limit = config->limit;
        sorted_merge->sort_type = config->sort_type;
        sorted_merge->delimiter = config->delimiter;
        sorted_merge->result.reserve(config->limit);
    }

    static inline void deinit(void *mem)
    {
        Sorted_merge_data<T, K> *sorted_merge = static_cast<Sorted_merge_data<T, K> *>(mem);
        sorted_merge->~Sorted_merge_data<T, K>();
    }

    static inline const void *postprocessing(void *mem, std::size_t& elem_cnt)
    {
        Sorted_merge_data<T, K> *sorted_merge = static_cast<Sorted_merge_data<T, K>*>(mem);
        Sort_type sort_type = sorted_merge->sort_type;
        sort(sorted_merge->data.begin(), sorted_merge->data.end(), [&sort_type](const std::pair<T,K>& a, const std::pair<T,K>& b) -> bool { 
            if (sort_type == ASCENDING)
                return a.second < b.second;
            else
                return a.second > b.second;
            }); 

        for (auto it = sorted_merge->data.begin(); it != sorted_merge->data.end(); it++) {
            if (sorted_merge->result.size() == sorted_merge->limit)
                break;
            sorted_merge->result.emplace_back(it->first);
        }

        elem_cnt = sorted_merge->result.size();
        return sorted_merge->result.data();
    }    
};

template <typename T, typename K>
struct Sorted_merge_dir_data : Config_sorted_merge {
    std::vector<std::pair<T, K>> data;
    std::vector<T> result;
    
    static inline void init(void *mem, const void *cfg)
    {
        Sorted_merge_dir_data<T, K> *sorted_merge = new(mem) Sorted_merge_dir_data<T, K>();
        const Config_sorted_merge *config = static_cast<const Config_sorted_merge *>(cfg);
        sorted_merge->limit = config->limit;
        sorted_merge->sort_type = config->sort_type;
        sorted_merge->delimiter = config->delimiter;
        sorted_merge->result.reserve(config->limit);
    }

    static inline void deinit(void *mem)
    {
        Sorted_merge_dir_data<T, K> *sorted_merge = static_cast<Sorted_merge_dir_data<T, K> *>(mem);
        sorted_merge->~Sorted_merge_dir_data<T, K>();
    }

    static inline const void *postprocessing(void *mem, std::size_t& elem_cnt, bool is_reverse)
    {
        Sorted_merge_dir_data<T, K> *sorted_merge = static_cast<Sorted_merge_dir_data<T, K>*>(mem);
        Sort_type sort_type = sorted_merge->sort_type;
        sort(sorted_merge->data.begin(), sorted_merge->data.end(), [&sort_type](const std::pair<T,K>& a, const std::pair<T,K>& b) -> bool { 
            if (sort_type == ASCENDING)
                return a.second < b.second;
            else
                return a.second > b.second;
            }); 

        for (auto it = sorted_merge->data.begin(); it != sorted_merge->data.end(); it++) {
            if (sorted_merge->result.size() == sorted_merge->limit)
                break;
            if (is_reverse)
                sorted_merge->result.emplace_back(-(it->first));
            else
                sorted_merge->result.emplace_back(it->first);
        }

        elem_cnt = sorted_merge->result.size();
        return sorted_merge->result.data();
    }    
};

/**
 * @brief Makes sum of values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template<typename T>
inline void sum(const void *src, void *dst) noexcept
{
    Basic_data<T> *sum = static_cast<Basic_data<T>*>(dst);
    sum->data += *(static_cast<const T*>(src));
}

/**
 * @brief Store min value from values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template<typename T>
inline void min(const void *src, void *dst) noexcept
{
    Basic_data<T> *min = static_cast<Basic_data<T>*>(dst);
    if (*(static_cast<const T*>(src)) < min->data)
        min->data = *(static_cast<const T*>(src));
}

/**
 * @brief Store max value from values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template<typename T>
inline void max(const void *src, void *dst) noexcept
{
    Basic_data<T> *max = static_cast<Basic_data<T>*>(dst);
    if (*(static_cast<const T*>(src)) > max->data)
        max->data = *(static_cast<const T*>(src));
}

/**
 * @brief Store bitwise AND value from values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
inline void bitwise_and(const void *src, void *dst) noexcept
{
    First_init_data<T> *bit_and = static_cast<First_init_data<T>*>(dst);
    if (bit_and->is_set == false) {
        bit_and->data = *(static_cast<const T*>(src));
        bit_and->is_set = true;
    } else
        bit_and->data &= *(static_cast<const T*>(src));
}

/**
 * @brief Store bitwise OR value from values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
inline void bitwise_or(const void *src, void *dst) noexcept
{
    Basic_data<T> *bit_or = static_cast<Basic_data<T>*>(dst);
    bit_or->data |= *(static_cast<const T*>(src));
}

/**
 * @brief Store first seen value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
inline void first(const void *src, void *dst) noexcept
{
    First_init_data<T> *first = static_cast<First_init_data<T>*>(dst);
    if (first->is_set == false) {
        first->data = *(static_cast<const T*>(src));
        first->is_set = true;
    }
}

/**
 * @brief Store first seen string value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
inline void first_string(const void *src, void *dst) noexcept
{
    const ur_array_data *src_data = (static_cast<const ur_array_data*>(src));
    String_data *first = static_cast<String_data*>(dst);
    if (first->is_set == false) {
        first->data.insert(first->data.begin(), static_cast<const char*>(src_data->ptr_first), \
            static_cast<const char *>(src_data->ptr_first) + src_data->cnt_elements);
        first->is_set = true;
    }
}

/**
 * @brief Store first seen non-empty string value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
inline void first_non_empty_string(const void *src, void *dst) noexcept
{
    const ur_array_data *src_data = (static_cast<const ur_array_data*>(src));
    String_data *first = static_cast<String_data*>(dst);
    if (first->is_set == false && src_data->cnt_elements) {
        first->data.insert(first->data.begin(), static_cast<const char*>(src_data->ptr_first), \
            static_cast<const char *>(src_data->ptr_first) + src_data->cnt_elements);
        first->is_set = true;
    }
}

/**
 * @brief Store last seen string value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
inline void last_string(const void *src, void *dst) noexcept
{
    const ur_array_data *src_data = (static_cast<const ur_array_data*>(src));
    String_data *last = static_cast<String_data*>(dst);
    last->data.clear();
    last->data.insert(last->data.begin(), static_cast<const char*>(src_data->ptr_first), \
        static_cast<const char *>(src_data->ptr_first) + src_data->cnt_elements);
}

/**
 * @brief Store last seen non-empty string value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
inline void last_non_empty_string(const void *src, void *dst) noexcept
{
    const ur_array_data *src_data = (static_cast<const ur_array_data*>(src));
    String_data *last = static_cast<String_data*>(dst);
    if (src_data->cnt_elements) {
        last->data.clear();
        last->data.insert(last->data.begin(), static_cast<const char*>(src_data->ptr_first), \
            static_cast<const char *>(src_data->ptr_first) + src_data->cnt_elements);
    }
}

/**
 * @brief Store first seen non-empty value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
inline void first_non_empty(const void *src, void *dst) noexcept
{
    First_init_data<T> *first = static_cast<First_init_data<T>*>(dst);
    if (first->is_set == false && *(static_cast<const T*>(src))) {
        first->data = *(static_cast<const T*>(src));
        first->is_set = true;
    }
}

/**
 * @brief Store last seen value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
inline void last(const void *src, void *dst) noexcept
{
    Basic_data<T> *last = static_cast<Basic_data<T>*>(dst);
    last->data = *(static_cast<const T*>(src));
}

/**
 * @brief Store last seen non-empty value.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
inline void last_non_empty(const void *src, void *dst) noexcept
{
    Basic_data<T> *last = static_cast<Basic_data<T>*>(dst);
    if (*(static_cast<const T*>(src)))
        last->data = *(static_cast<const T*>(src));
}

/**
 * @brief Makes sum of values stored on src and dst pointers from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template<typename T>
inline void avg(const void *src, void *dst) noexcept
{
    Average_data<T> *avg = static_cast<Average_data<T>*>(dst);
    sum<T>(src, &avg->data);
    avg->cnt++;
}

/**
 * @brief Append values stored on src pointers to dst pointer from given type T.
 * @tparam T template type variable.
 * @param [in] src pointer to source of new data.
 * @param [in,out] dst pointer to already stored data which will be updated (modified).
 */
template <typename T>
inline void append(const void *src, void *dst) noexcept
{
    Append_data<T> *append = static_cast<Append_data<T>*>(dst);
    const ur_array_data *src_data = (static_cast<const ur_array_data*>(src));
    std::size_t appended_data_size = append->data.size();
    
    if (appended_data_size == append->limit)
        return;

    if (std::is_same<T, char>::value) {
        if (appended_data_size + src_data->cnt_elements + 1 > append->limit)
            return;
        append->data.insert(append->data.end(), static_cast<const T*>(src_data->ptr_first), \
            static_cast<const T*>(src_data->ptr_first) + src_data->cnt_elements);
        T *delimiter = (T *)&append->delimiter;
        append->data.emplace_back(*delimiter);
        return;
    }
    
    if (appended_data_size + src_data->cnt_elements > append->limit)
        append->data.insert(append->data.end(), static_cast<const T*>(src_data->ptr_first), \
            static_cast<const T*>(src_data->ptr_first) + append->limit - appended_data_size);
    else
        append->data.insert(append->data.end(), static_cast<const T*>(src_data->ptr_first), \
            static_cast<const T*>(src_data->ptr_first) + src_data->cnt_elements);
}

template <typename T, typename K>
inline void sorted_merge(const void *src, void *dst) noexcept
{
    Sorted_merge_data<T, K> *sorted_merge = static_cast<Sorted_merge_data<T, K>*>(dst);
    const ur_array_data *src_data = (static_cast<const ur_array_data*>(src));

    assert(src_data->sort_key_elements == src_data->cnt_elements);

    for (std::size_t i = 0; i < src_data->sort_key_elements; i++) {
        std::pair<T, K> t_k = std::make_pair(((T *)src_data->ptr_first)[i], ((K*)src_data->sort_key)[i]);
        sorted_merge->data.emplace_back(t_k);
    }
}

template <typename T, typename K>
inline void sorted_merge_dir(const void *src, void *dst) noexcept
{
    Sorted_merge_dir_data<T, K> *sorted_merge = static_cast<Sorted_merge_dir_data<T, K>*>(dst);
    const ur_array_dir_data *src_data = (static_cast<const ur_array_dir_data*>(src));

    assert(src_data->sort_key_elements == src_data->cnt_elements);

    for (std::size_t i = 0; i < src_data->sort_key_elements; i++) {
        T value = ((T *)src_data->ptr_first)[i];
        if (src_data->is_key_reversed) {
            value = -value;
        }
        std::pair<T, K> t_k = std::make_pair(value, ((K*)src_data->sort_key)[i]);
        sorted_merge->data.emplace_back(t_k);
    }
}

} // namespace agg

#endif // AGGREGATOR_FUNCTIONS_H
