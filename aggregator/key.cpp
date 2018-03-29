/*! \file key.cpp
 */
//
// Created by slabimic on 2/10/18.
//

#include "key.h"

/* ================================================================= */
/* ============= KeywordTemplate class definitions ================= */
/* ================================================================= */

/*
 * Static variables declaration, better than global variable
 */
int KeyTemplate::indexes_to_record [MAX_KEY_FIELDS];
uint KeyTemplate::used_fields = 0;
uint KeyTemplate::key_size = 0;

/* ----------------------------------------------------------------- */
void KeyTemplate::add_field(int record_id, int size)
{
   indexes_to_record[used_fields] = record_id;
   key_size += size;
   used_fields++;
}
/* ----------------------------------------------------------------- */
void KeyTemplate::reset()
{
   used_fields = 0;
   key_size = 0;
}

/* ================================================================= */
/* ================= Keyword class definitions ===================== */
/* ================================================================= */

Key::Key()
{
   data = new char [KeyTemplate::key_size + 1];
   data_length = 0;
}
/* ----------------------------------------------------------------- */
Key::~Key()
{
   if (data)
      delete [] data;
}
/* ----------------------------------------------------------------- */
Key::Key(const Key &other)
{
   data_length = other.data_length;
   data = new char[KeyTemplate::key_size + 1];
   memcpy(data, other.data, data_length);
}
/* ----------------------------------------------------------------- */
const char *Key::get_data() const
{
   return data;
}
/* ----------------------------------------------------------------- */
int Key::get_size() const
{
   return data_length;
}
/* ----------------------------------------------------------------- */
void Key::add_field(const void *src, int size)
{
   memcpy(data+data_length, src, size);
   data_length += size;
}
/* ----------------------------------------------------------------- */
bool operator< (const Key &a, const Key &b)
{
   /*
    * Assumption comparison only for use in map,
    * therefore both parameters have the same number of bytes written
    */
   return memcmp(a.data, b.data, a.data_length) < 0 ? true : false;
}
/* ----------------------------------------------------------------- */
bool operator== (const Key &a, const Key &b)
{
   return memcmp(a.data, b.data, a.data_length) == 0 ? true : false;
}