//
// Created by slabimic on 2/10/18.
//

#include "key.h"

/*
*  class definitions
*/
/* ================================================================= */
/* ============= KeywordTemplate class definitions ================= */
/* ================================================================= */

/*
 * Static variables declaration, better than global variable
 */
int KeyTemplate::indexes_to_record [MAX_KEY_FIELDS];
//int KeyTemplate::indexes_to_key [MAX_KEY_FIELDS];
int KeyTemplate::sizes_of_fields [MAX_KEY_FIELDS];
uint KeyTemplate::used_fields = 0;
uint KeyTemplate::key_size = 0;

/* ----------------------------------------------------------------- */
void KeyTemplate::add_field(int record_id, int size)
{
   indexes_to_record[used_fields] = record_id;
   sizes_of_fields[used_fields] = size;
   key_size += size;
  /*
   int tmp_index = 0;
   for(int i = 0; i < used_fields; i++) {
      tmp_index += sizes_of_fields[i];
   }
   indexes_to_key[used_fields] = tmp_index;
   */
   used_fields++;
}

/* ================================================================= */
/* ================= Keyword class definitions ===================== */
/* ================================================================= */

Key::Key()
{
   data = new char [KeyTemplate::key_size+1];
}
/* ----------------------------------------------------------------- */
Key::~Key()
{
   if (data)
      delete [] data;
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
   return memcmp(a.data, b.data, a.data_length);
}
