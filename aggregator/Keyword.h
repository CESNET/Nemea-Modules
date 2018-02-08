#include <zconf.h>

#ifndef AGGREGATOR_KEYWORD_H
#define AGGREGATOR_KEYWORD_H

#endif //AGGREGATOR_KEYWORD_H

#define MAX_KEY_FIELDS 32                 // Static maximal key members count
class Keyword;                            // Definition to allow use this class in Template

static class KeywordTemplate {
public:
    int indexesToRecord [MAX_KEY_FIELDS];
    int indexesToKeyword [MAX_KEY_FIELDS];
    int sizesOfFields [MAX_KEY_FIELDS];

    void print(Keyword key);
};

class Keyword {
private:
    char* keyString;                      // Only values from record
public:
    Keyword();
    ~Keyword();
    void addField();
    //compare();
    //hashCode();
};