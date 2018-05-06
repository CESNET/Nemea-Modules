/**
 * \file configuration.h
 * \brief Module running properties configuration.
 * \author Michal Slabihoudek <slabimic@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
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

#ifndef AGGREGATOR_CONFIGURATION_H
#define AGGREGATOR_CONFIGURATION_H
/** Default timeout length value.*/
#define DEFAULT_TIMEOUT 10

/** Aggregation function type value defining the key for aggregation.*/
#define KEY       0
/** Aggregation function type value defining sum.*/
#define SUM       1
/** Aggregation function type value defining average.*/
#define AVG       2
/** Aggregation function type value defining minimum.*/
#define MIN       3
/** Aggregation function type value defining maximum.*/
#define MAX       4
/** Aggregation function type value defining first .*/
#define FIRST     5
/** Aggregation function type value defining last.*/
#define LAST      6
/** Aggregation function type value defining bitwise or.*/
#define BIT_OR    7
/** Aggregation function type value defining bitwise and.*/
#define BIT_AND   8

/** Active timeout type value definition.*/
#define TIMEOUT_ACTIVE           0
/** Passive timeout type value definition.*/
#define TIMEOUT_PASSIVE          1
/** Global timeout type value definition.*/
#define TIMEOUT_GLOBAL           2
/** Mixed (active and passive) timeout type value definition.*/
#define TIMEOUT_ACTIVE_PASSIVE   3

/** Different timeout types count value definition.*/
#define TIMEOUT_TYPES_COUNT      3        // Count of different timeout types (active_passive dont use new type)

/** Static fields used by modules definitions.*/
#define STATIC_FIELDS "TIME_FIRST,TIME_LAST,COUNT"

#include "key.h"
#include "output.h"
/**
 * Simply class to create/hold configuration from user input.
 */
class Config {
private:
   int functions[MAX_KEY_FIELDS];        /*!< Aggregation/Key function type definition. */
   char *field_names[MAX_KEY_FIELDS];    /*!< Names of fields to work with. */
   int used_fields;                      /*!< Counter of fields to work with. */
   int timeout[TIMEOUT_TYPES_COUNT];     /*!< Lengths of various timeouts. */
   int timeout_type;                     /*!< Currently active timeout type to use. */
   bool variable_flag;                   /*!< Flag if variable length field presented to proccess. */
   /**
    * Compare new field with fields already set in cofiguration.
    * @param [in] field_name to compare with others
    * @return true if field is not already used by module, false if field is already configured.
    */
   bool verify_field(const char* field_name);
public:
    /**
     * Constructor with defaults values initialization.
     * Set timeout_type to 'Active' and all type values to 10 seconds.
     */
   Config();
    /**
     * Destructor of class, free allocated memory for field names.
     */
   ~Config();
    /**
     * Get current count of fields to process.
     * @return current used_fields value;
     */
   int get_used_fields();
    /**
     * Get name of configured field on given index.
     * @param [in] index to array of fields name.
     * @return pointer to name of fields on given index, Empty string "" if index is not between 0-used_fields.
     */
   const char * get_name(int index);
    /**
     * Get information whether variable length field is presented in fields to work with.
     * @return True if is var length field presented, False otherwise.
     */
   bool is_variable();
    /**
     * Set value of variable_flag to true or false.
     * @param [in] flag value of true or false to be set to class variable.
     */
   void set_variable(bool flag);
    /**
     * Get information whether field on given index is key for aggregation or other aggregation function assigned.
     * @param [in] index of field to ask if is the aggregation key.
     * @return True if field is aggregation key, False if not or index is not between 0-used_fields.
     */
   bool is_key(int index);
    /**
     * Get information whether field on given index has the given aggregation function type assigned.
     * @param [in] index of field to ask for the function type
     * @param [in] func_id type of aggregation function to compare with one on given index.
     * @return True if function from parameter is equal to one assigned on given index, false if not or index not between 0-used_fields.
     */
   bool is_func(int index, int func_id);
    /**
     * Return function implementation to assigned function type of field on given index.
     * @param [in] index of field to ask for function implementation.
     * @param [in] field_type of field on given index (type returned from ur_get_type()0.
     * @return Pointer to function which implements the assigned aggregation function type.
     */
   agg_func get_function_ptr(int index, ur_field_type_t field_type);
    /**
     * Return function implementation of specified field type for record postprocessing before sending.
     * @param [in] index of field to ask for function implementation.
     * @param [in] field_type of field on given index (type returned from ur_get_type()).
     * @return Pointer to function which implements the postprocessing function of specified field type.
     */
   final_avg get_avg_ptr(int index, ur_field_type_t field_type);
    /**
     * Add field from user input to module configuration.
     * @param [in] func aggregation function type to be assigned to the field of given name.
     * @param [in] field_name name of given field .
     */
   void add_member(int func, const char *field_name);
    /**
     * Get timeout value in seconds from given timeout type.
     * @param [in] type of timeout to ask for currently set value.
     * @return Length of given timeout type in seconds.
     */
   int get_timeout(int type);
    /**
     * Returns currently active timeout type.
     * @return integer meaning defined timeout type.
     */
   int get_timeout_type();
    /**
     * Set module timeout parameters from user input.
     * @param [in] input string defining module timeout configuration.
     */
   void set_timeout(const char *input);
    /**
     * Create UniRec output template field definition string from actual module configuration.
     * Received pointer needs to be freed.
     * @return Pointer to template field definition string.
     */
   char * return_template_def();
   /**
    * Print actual module configuration with assigned values.
    */
   void print();
};

#endif //AGGREGATOR_CONFIGURATION_H