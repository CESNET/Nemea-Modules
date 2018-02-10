#include <zconf.h>

#include <unirec/unirec.h>

#ifndef AGGREGATOR_KEYWORD_H
#define AGGREGATOR_KEYWORD_H

#endif //AGGREGATOR_KEYWORD_H

#define MAX_KEY_FIELDS 32                 // Static maximal key members count
class Keyword;                            // Definition to allow use this class in Template

class KeywordTemplate {
public:
    static uint indexesToRecord [MAX_KEY_FIELDS];
    static int indexesToKeyword [MAX_KEY_FIELDS];     // Global size value, will only work with static size fields
    static int sizesOfFields [MAX_KEY_FIELDS];        // Global size value, will only work with static size fields
    static uint usedFields;

    static void addField(const char* fieldName);
private:

};


class Keyword {
private:
    char* keyString;                      // Only values from record
    int keyStringSize = 0;                // Size of allocated memory for keyString, not length of written bytes
    int keyStringLength = 0;              // The length of written bytes
public:
    Keyword();
    ~Keyword();
    void fillKeyword(ur_template_t * inTmplt, const void* recvRecord);
    void flushKeyword(ur_template_t * outTmplt, void *outRecord);
    //compare();
    //hashCode();=
private:
    bool reallocateArray();               // always keyStringSize * 2 ??
    void addField();
};