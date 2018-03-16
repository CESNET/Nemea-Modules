/*! \file key.h
 */

#include <zconf.h>

#include <unirec/unirec.h>

#ifndef AGGREGATOR_KEYWORD_H
#define AGGREGATOR_KEYWORD_H

/**My Preprocessor Macro.*/
#define MAX_KEY_FIELDS 32                 // Static maximal key members count

/**
 * Class description
 */
class KeyTemplate {
public:
   static int indexes_to_record [MAX_KEY_FIELDS];   /*!< Variable brief description. */
   static uint used_fields;                         /*!< Variable brief description. */
   static uint key_size;                            /*!< Variable brief description. */
   /**
    *
    * @param record_id
    * @param size
    */
   static void add_field(int record_id, int size);
   /**
    *
    */
   static void reset();
};

/**
 * Class description
 */
class Key {
private:
   char* data;                   /*!< Variable brief description. */ // Only values from record
   int data_length;              /*!< Variable brief description. */ // The length of written bytes
public:
   /**
    *
    */
   Key();
   /**
    *
    */
   ~Key();
   /**
    *
    * @param other
    */
   Key(const Key &other);
   /**
    *
    * @param src
    * @param size
    */
   void add_field(const void *src, int size);            // Append new field into record
   /**
    *
    * @param a
    * @param b
    * @return
    */
   friend bool operator< (const Key &a, const Key &b);  // Key needs to be comparable for the map
   //hash_code();
   /**
    *
    */
   void print() const;
};

#endif //AGGREGATOR_KEYWORD_H