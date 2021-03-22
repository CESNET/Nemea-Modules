/**
 * @file agregator_fields.cpp
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief 
 * @version 0.1
 * @date 31.8.2020
 *   
 * @copyright Copyright (c) 2020 CESNET
 */

#include "aggregator.h"
#include "aggregator_functions.h"
#include "macaddr.h"

#include <limits>
#include <cassert>

using namespace agg;

void Flow_data::update(const time_t first, const time_t last, const uint32_t cnt, bool is_reverse) noexcept
{
    count += cnt;
    if (time_first > first) {
        time_first = first;
        reverse = is_reverse;
    }
    if (time_last < last)
        time_last = last;
}

Flow_data::Flow_data()
{
    count = 0;
    time_last = 0;
    time_first = std::numeric_limits<time_t>::max();
}

const void *Field::post_processing(void *ag_data, std::size_t& typename_size, std::size_t& elem_cnt)
{
    typename_size = this->typename_size;
    if (post_proc_fnc)
        return post_proc_fnc(ag_data, elem_cnt);

    elem_cnt = 1;
    return static_cast<const void *>(ag_data);
}

void Field::aggregate(const void *src, void *dst)
{
    ag_fnc(src, dst);
}

void Field::init(void *tmplt_mem, const void *cfg)
{
    init_fnc(tmplt_mem, cfg);
}

void Field::deinit(void *src)
{
    deinit_fnc(src);
}

template<typename T, typename K>
int Field_template::assign() noexcept
{
    ag_fnc = sorted_merge<T, K>;
    post_proc_fnc = Sorted_merge_data<T, K>::postprocessing;
    typename_size = sizeof(T);
    init_fnc = Sorted_merge_data<T, K>::init;
    deinit_fnc = Sorted_merge_data<T, K>::deinit;
    ag_data_size = sizeof(Sorted_merge_data<T, K>);
    return 0;
}

template<Field_type ag_type>
int Field_template::assign_first_string() noexcept
{
    if (ag_type == FIRST)
        ag_fnc = first_string;
    else
        ag_fnc = first_non_empty_string;
    post_proc_fnc = String_data::postprocessing;
    typename_size = sizeof(char);
    init_fnc = String_data::init;
    deinit_fnc = String_data::deinit;
    ag_data_size = sizeof(String_data);
    return 0;
}

template<Field_type ag_type, typename T>
int Field_template::assign_first() noexcept
{
    if (ag_type == FIRST)
        ag_fnc = first<T>;
    else
        ag_fnc = first_non_empty<T>;
    post_proc_fnc = nullptr;
    typename_size = sizeof(T);
    init_fnc = First_init_data<T>::init;
    deinit_fnc = First_init_data<T>::deinit;
    ag_data_size = sizeof(First_init_data<T>);
    return 0;
}

template<Field_type ag_type, typename T>
int Field_template::assign_last() noexcept
{
    if (ag_type == LAST)
        ag_fnc = last<T>;
    else
        ag_fnc = last_non_empty<T>;
    post_proc_fnc = nullptr;
    typename_size = sizeof(T);
    init_fnc = Basic_data<T>::init;
    deinit_fnc = Basic_data<T>::deinit;
    ag_data_size = sizeof(Basic_data<T>);
    return 0;
}

template<Field_type ag_type>
int Field_template::assign_last_string() noexcept
{
    if (ag_type == LAST)
        ag_fnc = last_string;
    else
        ag_fnc = last_non_empty_string;
    post_proc_fnc = String_data::postprocessing;
    typename_size = sizeof(char);
    init_fnc = String_data::init;
    deinit_fnc = String_data::deinit;
    ag_data_size = sizeof(String_data);
    return 0;
}

template<Field_type ag_type, typename T>
int Field_template::assign_bitor_bitand() noexcept
{
    if (ag_type == BIT_AND) {
        ag_fnc = bitwise_and<T>;
        init_fnc = First_init_data<T>::init;
        deinit_fnc = First_init_data<T>::deinit;
        ag_data_size = sizeof(First_init_data<T>);
    } else {
        ag_fnc = bitwise_or<T>;
        init_fnc = Basic_data<T>::init;
        deinit_fnc = Basic_data<T>::deinit;
        ag_data_size = sizeof(Basic_data<T>);
    }
    post_proc_fnc = nullptr;
    typename_size = sizeof(T);
    return 0;
}

template<typename T>
int Field_template::assign_append() noexcept
{
    typename_size = sizeof(T);
    ag_fnc = append<T>;
    post_proc_fnc = Append_data<T>::postprocessing;
    init_fnc = Append_data<T>::init;
    deinit_fnc = Append_data<T>::deinit;
    ag_data_size = sizeof(Append_data<T>);
    return 0;
}

template<Field_type ag_type, typename T>
int Field_template::assign_min_max() noexcept
{
    if (ag_type == MIN)
        ag_fnc = min<T>;
    else
        ag_fnc = max<T>;
    typename_size = sizeof(T);
    post_proc_fnc = nullptr;
    init_fnc = Basic_data<T>::init;
    deinit_fnc = Basic_data<T>::deinit;
    ag_data_size = sizeof(Basic_data<T>);
    return 0; 
}

template<typename T>
int Field_template::assign_avg() noexcept
{
    typename_size = sizeof(T);
    ag_fnc = avg<T>;
    post_proc_fnc = Average_data<T>::postprocessing;
    init_fnc = Average_data<T>::init;
    deinit_fnc = Average_data<T>::deinit;
    ag_data_size = sizeof(Average_data<T>);
    return 0; 
}

template<typename T>
int Field_template::assign_sum() noexcept
{
    typename_size = sizeof(T);
    ag_fnc = sum<T>;
    post_proc_fnc = nullptr;
    init_fnc = Basic_data<T>::init;
    deinit_fnc = Basic_data<T>::deinit;
    ag_data_size = sizeof(Basic_data<T>);
    return 0; 
}

int Field_template::set_templates(const Field_type ag_type, const ur_field_type_t ur_f_type)
{
    switch (ag_type) {
    case SUM:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_sum<char>();
        case UR_TYPE_UINT8:  return assign_sum<uint8_t>();
        case UR_TYPE_INT8:   return assign_sum<int8_t>();
        case UR_TYPE_UINT16: return assign_sum<uint16_t>();
        case UR_TYPE_INT16:  return assign_sum<int16_t>();
        case UR_TYPE_UINT32: return assign_sum<uint32_t>();
        case UR_TYPE_INT32:  return assign_sum<int32_t>();
        case UR_TYPE_UINT64: return assign_sum<uint64_t>();
        case UR_TYPE_INT64:  return assign_sum<int64_t>();
        case UR_TYPE_FLOAT:  return assign_sum<float>();
        case UR_TYPE_DOUBLE: return assign_sum<double>();
        default:
            std::cerr << "Only char, int, uint, float and double can be used to SUM function." << std::endl;
            return 1;
        }
    case AVG:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_avg<char>();
        case UR_TYPE_UINT8:  return assign_avg<uint8_t>();
        case UR_TYPE_INT8:   return assign_avg<int8_t>();
        case UR_TYPE_UINT16: return assign_avg<uint16_t>();
        case UR_TYPE_INT16:  return assign_avg<int16_t>();
        case UR_TYPE_UINT32: return assign_avg<uint32_t>();
        case UR_TYPE_INT32:  return assign_avg<int32_t>();
        case UR_TYPE_UINT64: return assign_avg<uint64_t>();
        case UR_TYPE_INT64:  return assign_avg<int64_t>();
        case UR_TYPE_FLOAT:  return assign_avg<float>();
        case UR_TYPE_DOUBLE: return assign_avg<double>();
        default:
            std::cerr << "Only char, int, uint, float and double can be used to AVG function." << std::endl;
            return 1;
        }
    case MIN:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_min_max<MIN, char>();
        case UR_TYPE_UINT8:  return assign_min_max<MIN, uint8_t>();
        case UR_TYPE_INT8:   return assign_min_max<MIN, int8_t>();
        case UR_TYPE_UINT16: return assign_min_max<MIN, uint16_t>();
        case UR_TYPE_INT16:  return assign_min_max<MIN, int16_t>();
        case UR_TYPE_UINT32: return assign_min_max<MIN, uint32_t>();
        case UR_TYPE_INT32:  return assign_min_max<MIN, int32_t>();
        case UR_TYPE_UINT64: return assign_min_max<MIN, uint64_t>();
        case UR_TYPE_INT64:  return assign_min_max<MIN, int64_t>();
        case UR_TYPE_FLOAT:  return assign_min_max<MIN, float>();
        case UR_TYPE_DOUBLE: return assign_min_max<MIN, double>();
        case UR_TYPE_TIME:   return assign_min_max<MIN, time_t>();
        case UR_TYPE_IP:     return assign_min_max<MIN, uint128_t>();
        case UR_TYPE_MAC:    
        std::cout << "MACCC\n";
        return assign_min_max<MIN, Mac_addr>();
        default:
            std::cerr << "Only char, int, uint, float, double, time, mac and ip can be used to MIN function." << std::endl;
            return 1;
        }
    case MAX:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_min_max<MAX, char>();
        case UR_TYPE_UINT8:  return assign_min_max<MAX, uint8_t>();
        case UR_TYPE_INT8:   return assign_min_max<MAX, int8_t>();
        case UR_TYPE_UINT16: return assign_min_max<MAX, uint16_t>();
        case UR_TYPE_INT16:  return assign_min_max<MAX, int16_t>();
        case UR_TYPE_UINT32: return assign_min_max<MAX, uint32_t>();
        case UR_TYPE_INT32:  return assign_min_max<MAX, int32_t>();
        case UR_TYPE_UINT64: return assign_min_max<MAX, uint64_t>();
        case UR_TYPE_INT64:  return assign_min_max<MAX, int64_t>();
        case UR_TYPE_FLOAT:  return assign_min_max<MAX, float>();
        case UR_TYPE_DOUBLE: return assign_min_max<MAX, double>();
        case UR_TYPE_TIME:   return assign_min_max<MAX, time_t>();
        case UR_TYPE_IP:     return assign_min_max<MAX, uint128_t>();
        case UR_TYPE_MAC:    return assign_min_max<MAX, Mac_addr>();
        default:
            std::cerr << "Only char, int, uint, float, double, time, mac and ip can be used to MAX function." << std::endl;
            return 1;
        }
    case FIRST:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_first<FIRST, char>();
        case UR_TYPE_UINT8:  return assign_first<FIRST, uint8_t>();
        case UR_TYPE_INT8:   return assign_first<FIRST, int8_t>();
        case UR_TYPE_UINT16: return assign_first<FIRST, uint16_t>();
        case UR_TYPE_INT16:  return assign_first<FIRST, int16_t>();
        case UR_TYPE_UINT32: return assign_first<FIRST, uint32_t>();
        case UR_TYPE_INT32:  return assign_first<FIRST, int32_t>();
        case UR_TYPE_UINT64: return assign_first<FIRST, uint64_t>();
        case UR_TYPE_INT64:  return assign_first<FIRST, int64_t>();
        case UR_TYPE_FLOAT:  return assign_first<FIRST, float>();
        case UR_TYPE_DOUBLE: return assign_first<FIRST, double>();
        case UR_TYPE_IP:     return assign_first<FIRST, uint128_t>();
        case UR_TYPE_MAC:    return assign_first<FIRST, Mac_addr>();
        case UR_TYPE_STRING: return assign_first_string<FIRST>();
        default:
            std::cerr << "Only char, int, uint, float, double, mac and ip can be used to FIRST function." << std::endl;
            return 1;
        }
    case FIRST_NON_EMPTY:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_first<FIRST_NON_EMPTY, char>();
        case UR_TYPE_UINT8:  return assign_first<FIRST_NON_EMPTY, uint8_t>();
        case UR_TYPE_INT8:   return assign_first<FIRST_NON_EMPTY, int8_t>();
        case UR_TYPE_UINT16: return assign_first<FIRST_NON_EMPTY, uint16_t>();
        case UR_TYPE_INT16:  return assign_first<FIRST_NON_EMPTY, int16_t>();
        case UR_TYPE_UINT32: return assign_first<FIRST_NON_EMPTY, uint32_t>();
        case UR_TYPE_INT32:  return assign_first<FIRST_NON_EMPTY, int32_t>();
        case UR_TYPE_UINT64: return assign_first<FIRST_NON_EMPTY, uint64_t>();
        case UR_TYPE_INT64:  return assign_first<FIRST_NON_EMPTY, int64_t>();
        case UR_TYPE_FLOAT:  return assign_first<FIRST_NON_EMPTY, float>();
        case UR_TYPE_DOUBLE: return assign_first<FIRST_NON_EMPTY, double>();
        case UR_TYPE_IP:     return assign_first<FIRST_NON_EMPTY, uint128_t>();
        case UR_TYPE_MAC:    return assign_first<FIRST_NON_EMPTY, Mac_addr>();
        case UR_TYPE_STRING: return assign_first_string<FIRST_NON_EMPTY>();
        default:
            std::cerr << "Only char, int, uint, float, double, mac and ip can be used to FIRST_NON_EMPTY function." << std::endl;
            return 1;
        }
    case LAST:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_last<LAST, char>();
        case UR_TYPE_UINT8:  return assign_last<LAST, uint8_t>();
        case UR_TYPE_INT8:   return assign_last<LAST, int8_t>();
        case UR_TYPE_UINT16: return assign_last<LAST, uint16_t>();
        case UR_TYPE_INT16:  return assign_last<LAST, int16_t>();
        case UR_TYPE_UINT32: return assign_last<LAST, uint32_t>();
        case UR_TYPE_INT32:  return assign_last<LAST, int32_t>();
        case UR_TYPE_UINT64: return assign_last<LAST, uint64_t>();
        case UR_TYPE_INT64:  return assign_last<LAST, int64_t>();
        case UR_TYPE_FLOAT:  return assign_last<LAST, float>();
        case UR_TYPE_DOUBLE: return assign_last<LAST, double>();
        case UR_TYPE_IP:     return assign_last<LAST, uint128_t>();
        case UR_TYPE_MAC:    return assign_last<LAST, Mac_addr>();
        case UR_TYPE_STRING: return assign_last_string<LAST>();
        default:
            std::cerr << "Only char, int, uint, float, double, mac and ip can be used to FIRST function." << std::endl;
            return 1;
        }
    case LAST_NON_EMPTY:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_last<LAST_NON_EMPTY, char>();
        case UR_TYPE_UINT8:  return assign_last<LAST_NON_EMPTY, uint8_t>();
        case UR_TYPE_INT8:   return assign_last<LAST_NON_EMPTY, int8_t>();
        case UR_TYPE_UINT16: return assign_last<LAST_NON_EMPTY, uint16_t>();
        case UR_TYPE_INT16:  return assign_last<LAST_NON_EMPTY, int16_t>();
        case UR_TYPE_UINT32: return assign_last<LAST_NON_EMPTY, uint32_t>();
        case UR_TYPE_INT32:  return assign_last<LAST_NON_EMPTY, int32_t>();
        case UR_TYPE_UINT64: return assign_last<LAST_NON_EMPTY, uint64_t>();
        case UR_TYPE_INT64:  return assign_last<LAST_NON_EMPTY, int64_t>();
        case UR_TYPE_FLOAT:  return assign_last<LAST_NON_EMPTY, float>();
        case UR_TYPE_DOUBLE: return assign_last<LAST_NON_EMPTY, double>();
        case UR_TYPE_IP:     return assign_last<LAST_NON_EMPTY, uint128_t>();
        case UR_TYPE_MAC:    return assign_last<LAST_NON_EMPTY, Mac_addr>();
        case UR_TYPE_STRING: return assign_last_string<LAST_NON_EMPTY>();
        default:
            std::cerr << "Only char, int, uint, float, double, mac and ip can be used to FIRST function." << std::endl;
            return 1;
        }
    case BIT_AND:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_bitor_bitand<BIT_AND, char>();
        case UR_TYPE_UINT8:  return assign_bitor_bitand<BIT_AND, uint8_t>();
        case UR_TYPE_INT8:   return assign_bitor_bitand<BIT_AND, int8_t>();
        case UR_TYPE_UINT16: return assign_bitor_bitand<BIT_AND, uint16_t>();
        case UR_TYPE_INT16:  return assign_bitor_bitand<BIT_AND, int16_t>();
        case UR_TYPE_UINT32: return assign_bitor_bitand<BIT_AND, uint32_t>();
        case UR_TYPE_INT32:  return assign_bitor_bitand<BIT_AND, int32_t>();
        case UR_TYPE_UINT64: return assign_bitor_bitand<BIT_AND, uint64_t>();
        case UR_TYPE_INT64:  return assign_bitor_bitand<BIT_AND, int64_t>();
        default:
            std::cerr << "Only char, int and uint can be used to BIT AND function." << std::endl;
            return 1;
        }
    case BIT_OR:
        switch (ur_f_type) {
        case UR_TYPE_CHAR:   return assign_bitor_bitand<BIT_OR, char>();
        case UR_TYPE_UINT8:  return assign_bitor_bitand<BIT_OR, uint8_t>();
        case UR_TYPE_INT8:   return assign_bitor_bitand<BIT_OR, int8_t>();
        case UR_TYPE_UINT16: return assign_bitor_bitand<BIT_OR, uint16_t>();
        case UR_TYPE_INT16:  return assign_bitor_bitand<BIT_OR, int16_t>();
        case UR_TYPE_UINT32: return assign_bitor_bitand<BIT_OR, uint32_t>();
        case UR_TYPE_INT32:  return assign_bitor_bitand<BIT_OR, int32_t>();
        case UR_TYPE_UINT64: return assign_bitor_bitand<BIT_OR, uint64_t>();
        case UR_TYPE_INT64:  return assign_bitor_bitand<BIT_OR, int64_t>();
        default:
            std::cerr << "Only char, int and uint can be used to BIT OR function." << std::endl;
            return 1;
        }
    case APPEND:
        switch (ur_f_type) {
        case UR_TYPE_A_UINT8:  return assign_append<uint8_t>();
        case UR_TYPE_A_INT8:   return assign_append<int8_t>();
        case UR_TYPE_A_UINT16: return assign_append<uint16_t>();
        case UR_TYPE_A_INT16:  return assign_append<int16_t>();
        case UR_TYPE_A_UINT32: return assign_append<uint32_t>();
        case UR_TYPE_A_INT32:  return assign_append<int32_t>();
        case UR_TYPE_A_UINT64: return assign_append<uint64_t>();
        case UR_TYPE_A_INT64:  return assign_append<int64_t>();
        case UR_TYPE_A_FLOAT:  return assign_append<float>();
        case UR_TYPE_A_DOUBLE: return assign_append<double>();
        case UR_TYPE_A_MAC:    return assign_append<Mac_addr>();
        case UR_TYPE_A_TIME:   return assign_append<time_t>();
        case UR_TYPE_STRING:   return assign_append<char>();
        case UR_TYPE_A_IP:     return assign_append<uint128_t>();
        default:
            std::cerr << "Only string and int, uint, float, double, mac, time, and IP array can be used to APPEND function." << std::endl;
            return 1;
        }
    default:
        assert("Invalid case option.\n");
        return 1;
    }
}

// TODO sorted append ur_array ur_array
int Field_template::set_templates(const ur_field_type_t ur_f_type, const ur_field_type_t ur_sort_key_f_type)
{
    switch (ur_f_type) {
    case UR_TYPE_A_UINT8:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<uint8_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<uint8_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<uint8_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<uint8_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<uint8_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<uint8_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<uint8_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<uint8_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<uint8_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<uint8_t, double>();
        case UR_TYPE_A_TIME:   return assign<uint8_t, time_t>();
        case UR_TYPE_A_IP:     return assign<uint8_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_INT8:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<int8_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<int8_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<int8_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<int8_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<int8_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<int8_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<int8_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<int8_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<int8_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<int8_t, double>();
        case UR_TYPE_A_TIME:   return assign<int8_t, time_t>();
        case UR_TYPE_A_IP:     return assign<int8_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_UINT16:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<uint16_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<uint16_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<uint16_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<uint16_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<uint16_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<uint16_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<uint16_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<uint16_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<uint16_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<uint16_t, double>();
        case UR_TYPE_A_TIME:   return assign<uint16_t, time_t>();
        case UR_TYPE_A_IP:     return assign<uint16_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_INT16:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<int16_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<int16_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<int16_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<int16_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<int16_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<int16_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<int16_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<int16_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<int16_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<int16_t, double>();
        case UR_TYPE_A_TIME:   return assign<int16_t, time_t>();
        case UR_TYPE_A_IP:     return assign<int16_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_UINT32:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<uint32_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<uint32_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<uint32_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<uint32_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<uint32_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<uint32_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<uint32_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<uint32_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<uint32_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<uint32_t, double>();
        case UR_TYPE_A_TIME:   return assign<uint32_t, time_t>();
        case UR_TYPE_A_IP:     return assign<uint32_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_INT32:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<int32_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<int32_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<int32_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<int32_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<int32_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<int32_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<int32_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<int32_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<int32_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<int32_t, double>();
        case UR_TYPE_A_TIME:   return assign<int32_t, time_t>();
        case UR_TYPE_A_IP:     return assign<int32_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_UINT64:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<uint64_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<uint64_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<uint64_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<uint64_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<uint64_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<uint64_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<uint64_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<uint64_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<uint64_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<uint64_t, double>();
        case UR_TYPE_A_TIME:   return assign<uint64_t, time_t>();
        case UR_TYPE_A_IP:     return assign<uint64_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_INT64:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<int64_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<int64_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<int64_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<int64_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<int64_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<int64_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<int64_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<int64_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<int64_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<int64_t, double>();
        case UR_TYPE_A_TIME:   return assign<int64_t, time_t>();
        case UR_TYPE_A_IP:     return assign<int64_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_FLOAT:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<float, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<float, int8_t>();
        case UR_TYPE_A_UINT16: return assign<float, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<float, int16_t>();
        case UR_TYPE_A_UINT32: return assign<float, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<float, int32_t>();
        case UR_TYPE_A_UINT64: return assign<float, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<float, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<float, float>();
        case UR_TYPE_A_DOUBLE: return assign<float, double>();
        case UR_TYPE_A_TIME:   return assign<float, time_t>();
        case UR_TYPE_A_IP:     return assign<float, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_DOUBLE:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<double, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<double, int8_t>();
        case UR_TYPE_A_UINT16: return assign<double, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<double, int16_t>();
        case UR_TYPE_A_UINT32: return assign<double, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<double, int32_t>();
        case UR_TYPE_A_UINT64: return assign<double, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<double, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<double, float>();
        case UR_TYPE_A_DOUBLE: return assign<double, double>();
        case UR_TYPE_A_TIME:   return assign<double, time_t>();
        case UR_TYPE_A_IP:     return assign<double, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_IP:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<uint128_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<uint128_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<uint128_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<uint128_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<uint128_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<uint128_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<uint128_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<uint128_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<uint128_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<uint128_t, double>();
        case UR_TYPE_A_TIME:   return assign<uint128_t, time_t>();
        case UR_TYPE_A_IP:     return assign<uint128_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_MAC:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<Mac_addr, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<Mac_addr, int8_t>();
        case UR_TYPE_A_UINT16: return assign<Mac_addr, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<Mac_addr, int16_t>();
        case UR_TYPE_A_UINT32: return assign<Mac_addr, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<Mac_addr, int32_t>();
        case UR_TYPE_A_UINT64: return assign<Mac_addr, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<Mac_addr, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<Mac_addr, float>();
        case UR_TYPE_A_DOUBLE: return assign<Mac_addr, double>();
        case UR_TYPE_A_TIME:   return assign<Mac_addr, time_t>();
        case UR_TYPE_A_IP:     return assign<Mac_addr, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_A_TIME:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<time_t, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<time_t, int8_t>();
        case UR_TYPE_A_UINT16: return assign<time_t, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<time_t, int16_t>();
        case UR_TYPE_A_UINT32: return assign<time_t, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<time_t, int32_t>();
        case UR_TYPE_A_UINT64: return assign<time_t, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<time_t, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<time_t, float>();
        case UR_TYPE_A_DOUBLE: return assign<time_t, double>();
        case UR_TYPE_A_TIME:   return assign<time_t, time_t>();
        case UR_TYPE_A_IP:     return assign<time_t, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    case UR_TYPE_STRING:
        switch (ur_sort_key_f_type) {
        case UR_TYPE_A_UINT8:  return assign<char, uint8_t>();
        case UR_TYPE_A_INT8:   return assign<char, int8_t>();
        case UR_TYPE_A_UINT16: return assign<char, uint16_t>();
        case UR_TYPE_A_INT16:  return assign<char, int16_t>();
        case UR_TYPE_A_UINT32: return assign<char, uint32_t>();
        case UR_TYPE_A_INT32:  return assign<char, int32_t>();
        case UR_TYPE_A_UINT64: return assign<char, uint64_t>();
        case UR_TYPE_A_INT64:  return assign<char, int64_t>();
        case UR_TYPE_A_FLOAT:  return assign<char, float>();
        case UR_TYPE_A_DOUBLE: return assign<char, double>();
        case UR_TYPE_A_TIME:   return assign<char, time_t>();
        case UR_TYPE_A_IP:     return assign<char, uint128_t>();
        default: 
            std::cerr << "Only array of int, uint, float, double, ip, mac and time can be used as SORTED_MERGE key." << std::endl;
            return 1;
        }
        break;
    default:
        std::cerr << "TODO." << std::endl;
        return 1;
    }
}

Field::Field(const Field_config cfg, const ur_field_id_t ur_fid, const ur_field_id_t ur_r_fid) :
    ur_fid(ur_fid), ur_r_fid(ur_r_fid)
{
    ur_field_type_t ur_field_type = ur_get_type(ur_fid);

    name = cfg.name;
    reverse_name = cfg.reverse_name;
    type = cfg.type;
    sort_name = cfg.sort_name;
    delimiter = cfg.delimiter;
    sort_type = cfg.sort_type;
    limit = cfg.limit;

    if (type == SORTED_MERGE) {
        ur_sort_key_id = ur_get_id_by_name(sort_name.c_str());
        if (ur_sort_key_id == UR_E_INVALID_NAME) {
            throw std::runtime_error("Invalid sort key type.");
        }
        ur_sort_key_type = ur_get_type(ur_sort_key_id);
        if (set_templates(ur_field_type, ur_sort_key_type))
            throw std::runtime_error("Cannot set field template.");
    } else {
        if (set_templates(type, ur_field_type))
            throw std::runtime_error("Cannot set field template.");
    }
}


void Fields::add_field(Field field)
{
    _fields.emplace_back(std::make_pair(field, _offset));
    _offset += field.ag_data_size;
}

void Fields::reset() noexcept
{
    _fields.clear();
    _offset = 0;
}

std::vector<std::pair<Field, std::size_t>> Fields::get_fields() noexcept 
{
    return _fields;
}

std::size_t Fields::get_size() noexcept
{
    return _offset;
}

void Fields::init(uint8_t *memory)
{
    for (auto data : _fields) {
        switch (data.first.type) {
        case SUM:
        case MAX:
        case BIT_AND:
        case BIT_OR:
        case FIRST:
        case FIRST_NON_EMPTY:
        case LAST:
        case LAST_NON_EMPTY:
        case AVG:
            data.first.init(memory, nullptr);
            break;
        case MIN:
            data.first.init(memory, memory);
            break;
        case APPEND: {
            struct Config_append cfg = {data.first.limit, data.first.delimiter};
            data.first.init(memory, &cfg);
            break;
        }
        case SORTED_MERGE: {
            struct Config_sorted_merge cfg = {data.first.limit, data.first.delimiter, data.first.sort_type};
            data.first.init(memory, &cfg);
            break;
        }
        default:
            assert("Invalid case option.\n");
        }
        memory = memory + data.first.ag_data_size;
    }
}

void Fields::deinit(uint8_t *memory)
{
    for (auto data : _fields) {
        data.first.deinit(memory);
        memory = memory + data.first.ag_data_size;
    }
}

Timeout_data::Timeout_data(FlowKey key, time_t passive_timeout, time_t active_timeout) :
    key(key), passive_timeout(passive_timeout), active_timeout(active_timeout)
{

}

std::vector<Context *> Flow_data_context_allocator::_ptrs;
std::size_t Flow_data_context_allocator::_idx = 0;
uint8_t* Flow_data_context_allocator::_global = nullptr;
std::function<void(uint8_t *)> Flow_data_context_allocator::_init_field = nullptr;
std::function<void(uint8_t *)> Flow_data_context_allocator::_deinit_field = nullptr;

void Flow_data_context_allocator::deinit()
{
    for (std::size_t i = 0; i < _ptrs.size(); i++) {
        _deinit_field(_ptrs[i]->data);
    }
    delete [] _global;
}

Flow_data_context_allocator::~Flow_data_context_allocator()
{
    for (std::size_t i = 0; i < _ptrs.size(); i++) {
        _deinit_field(_ptrs[i]->data);
    }
    delete [] _global;
}

void Flow_data_context_allocator::init(std::size_t elements, std::size_t data_size, std::function<void(uint8_t *)> init_field, std::function<void(uint8_t *)> deinit_field)
{
    std::size_t offset = 0;

    _init_field = init_field;
    _deinit_field = deinit_field;

    clear();

    _ptrs.reserve(elements);
    _global = new uint8_t[(data_size + sizeof(node<Timeout_data>)) * elements]();

    for (std::size_t i = 0; i < elements; i++) {
        Context *ctx = new (std::addressof(_global[offset])) Context;
        init_field(ctx->data);
        _ptrs.emplace_back(ctx);
        offset += data_size + sizeof(node<Timeout_data>);
    }
}

Context *Flow_data_context_allocator::get_ptr() noexcept
{
    return _ptrs[_idx++];
}

void Flow_data_context_allocator::release_ptr(Context *ptr) noexcept
{
    _deinit_field(ptr->data);
    _init_field(ptr->data);
    _ptrs[--_idx] = ptr;
}

void Flow_data_context_allocator::clear()
{
    for (std::size_t i = 0; i < _ptrs.size(); i++) {
        _deinit_field(_ptrs[i]->data);
    }
    delete [] _global;
    _global = nullptr;
    _idx = 0;
    _ptrs.clear();
}

namespace std {
    template<> class numeric_limits<Mac_addr> {
    public:
       static Mac_addr max() {return Mac_addr(true);};
    };
}
