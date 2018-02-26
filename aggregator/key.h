#include <zconf.h>

#include <unirec/unirec.h>

#ifndef AGGREGATOR_KEYWORD_H
#define AGGREGATOR_KEYWORD_H

#define MAX_KEY_FIELDS 32                 // Static maximal key members count

class KeyTemplate {
public:
    static int indexes_to_record [MAX_KEY_FIELDS];
    //static int indexes_to_key [MAX_KEY_FIELDS];     // Global size value, will only work with static size fields
    static int sizes_of_fields [MAX_KEY_FIELDS];        // Global size value, will only work with static size fields
    static uint used_fields;
    static uint key_size;

    static void add_field(int record_id, int size);
private:

};


class Key {
private:
    char* data;                      // Only values from record
    int data_length;              // The length of written bytes
public:
    Key();
    ~Key();
    void add_field(const void *src, int size);            // Append new field into record
    friend bool operator< (const Key &a, const Key &b);  // Key needs to be comparable for the map
    //hash_code();=
private:

};

#endif //AGGREGATOR_KEYWORD_H