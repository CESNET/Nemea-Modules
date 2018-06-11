/**
 * \file key.h
 * \brief Aggregation key and template.
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

#include <nemea-common/super_fast_hash.h>

#include <unirec/unirec.h>

#ifndef AGGREGATOR_KEYWORD_H
#define AGGREGATOR_KEYWORD_H

/** Maximal supported value of fields used to have aggregation function assigned.*/
#define MAX_KEY_FIELDS 32                 // Static maximal key members count

/**
 * Class to represent template for key class creation.
 */
class KeyTemplate {
public:
   static int indexes_to_record [MAX_KEY_FIELDS];   /*!< Field index from global unirec structure. */
   static uint used_fields;                         /*!< Count of stored and set fields in template. */
   static uint key_size;                            /*!< Sum of lengths of all fields set in template. */
   /**
    * Function to add (register) new field into template.
    * @param [in] record_id index of field from global unirec structure.
    * @param [in] size size of field with given id.
    */
   static void add_field(int record_id, int size);
   /**
    * Reset all fields to default (empty) state.
    */
   static void reset();
};

/**
 * Class to represent key for aggregation (key used in map).
 */
class Key {
private:
   char* data;                   /*!< Raw data value copies of all registered fields. */
   int data_length;              /*!< The length of written bytes into class data variable. */
public:
   /**
    * Constructor, allocates memory for storing the key values of KeyTemplate.key_size
    */
   Key();
   /**
    * Destructor, free allocated memory.
    */
   ~Key();
   /**
    * Copy constructor, to make copies to map storage.
    * @param [in] other source of data to be copied.
    */
   Key(const Key &other);
   /**
    * Access to private variable data representing key value as array of bytes.
    * @return const pointer to data array.
    */
   const char *get_data() const;
   /**
    * Get count of currently used bytes in key bytes array.
    * @return Length of written bytes.
    */
   int get_size() const;
   /**
    * Add values from source pointer to class data variable.
    * @param [in] src pointer to source data to be appended to key bytes array.
    * @param [in] size length of data in src pointer in bytes.
    */
   void add_field(const void *src, int size);            // Append new field into record
   /**
    * Overloaded operator less for easy class comparison in map.
    * @param [in] a first key element.
    * @param [in] b second key element.
    * @return True if parameter 'a' is less than parameter 'b'
    */
   friend bool operator< (const Key &a, const Key &b);  // Key needs to be comparable for the map
   /**
    * Overloaded operator equal for class comparison if less is not enough
    * @param [in] a first key element
    * @param [in] b second key element
    * @return True if if 'a' and 'b' are equal, false otherwise
    */
   friend bool operator== (const Key &a, const Key &b);  // Key needs to be comparable for the unordered_map
};

#endif //AGGREGATOR_KEYWORD_H