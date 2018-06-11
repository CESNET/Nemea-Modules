/**
 * \file key.cpp
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