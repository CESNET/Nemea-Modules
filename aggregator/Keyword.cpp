//
// Created by slabimic on 2/10/18.
//

#include "Keyword.h"

#define DEFAULT_KEY_SIZE 1024
/*
*  class definitions
*/
/* ================================================================= */
/* ============= KeywordTemplate class definitions ================= */
/* ================================================================= */

/*
 * Static variables declaration, better than global variable
 */
uint KeywordTemplate::indexesToRecord [MAX_KEY_FIELDS];
int KeywordTemplate::indexesToKeyword [MAX_KEY_FIELDS];
int KeywordTemplate::sizesOfFields [MAX_KEY_FIELDS];
uint KeywordTemplate::usedFields = 0;

/* ----------------------------------------------------------------- */
void KeywordTemplate::addField(const char *fieldName) {
/*
 * When received first message (ur_template)
 * 1) Process sanity check - check ur_fields name obtained from user
 *    whether they are present in received template
 *    a] if present, store the id, size to KeywordTemplate, count the
 *    indexToKeyword and increment usedFields
 */
}

/* ================================================================= */
/* ================= Keyword class definitions ===================== */
/* ================================================================= */

Keyword::Keyword() {
   keyStringSize = DEFAULT_KEY_SIZE;
   keyString = new char [DEFAULT_KEY_SIZE];
}
/* ----------------------------------------------------------------- */
Keyword::~Keyword() {
   if (keyString)
      delete [] keyString;
}
/* ----------------------------------------------------------------- */
void Keyword::fillKeyword(ur_template_t *inTmplt, const void *recvRecord) {
   /*
    * With every received ur_record go through stored indexesToRecord
    * and copy data from recvRecord to this.keyString
    */
}
/* ----------------------------------------------------------------- */
void Keyword::flushKeyword(ur_template_t *outTmplt, void *outRecord) {
   /*
    * Copy data from this.keyString to outRecord using outTmplt.
    * This means that I already have prepared outTmplt which contains
    * all fields from keyword and Processed fields.
    * The outTmplt will have different numeric ids for fields than
    * input, so need to get and save the out numeric ids for stored
    * fields using name of fields.
    *    > ur_get_name(field_id) to inTmplt => get the name (char*)
    *    > How to set data to outTmplt when no F_ makros defined?
   */
}
/* ----------------------------------------------------------------- */
bool Keyword::reallocateArray() {
   int oldSize = keyStringSize;
   keyStringSize *= 2;
   char* tmp = new char[keyStringSize];
   memcpy(tmp, keyString, oldSize);
   delete [] keyString;
   keyString = tmp;
   return false;
}
/* ----------------------------------------------------------------- */
void Keyword::addField() {

}
/* ----------------------------------------------------------------- */