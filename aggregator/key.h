/*! \file key.h
 */

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
   //hash_code();
   /**
    * Development key print value. No universal usage, implementation need to be modified for desired data type.
    */
   void print() const;
};

#endif //AGGREGATOR_KEYWORD_H