%option noyywrap

%{
    #include "parser.tab.h"
    #include <string.h>

    char *copyString(char* str, int len)
    {
        char *ret = calloc(len+1, sizeof(char));
        strcpy(ret, str);
        return ret;
    }
    char *cutString(char* str, int len)
    {
        char *ret = calloc(len-1, sizeof(char));
        strncpy(ret, str+1, (size_t)len-2);
        return ret;
    }
%}

NUM [0-9]{1,3}
HEX [0-9a-fA-F]{0,4}
%%

">"|"<"|"=<"|"<="|">="|"=>"                              { yylval.string = copyString(yytext, yyleng); return CMP; }
"="|"=="|"!="|"<>"|"=~"                                  { yylval.string = copyString(yytext, yyleng); return EQ; }
"||"|"Or"|"or"|"OR"                                      { yylval.number = 1; return OPERATOR;}
"&&"|"And"|"and"|"AND"                                   { yylval.number = 2; return OPERATOR;}
-?[0-9]+                                                 { yylval.number = atoi(yytext); return NUMBER; }
{NUM}\.{NUM}\.{NUM}\.{NUM}                               { yylval.string = copyString(yytext, yyleng); return IP; }
{HEX}\:{HEX}\:{HEX}\:{HEX}\:{HEX}\:{HEX}\:{HEX}\:{HEX}   { yylval.string = copyString(yytext, yyleng); return IP; }
"PROTOCOL"                                               { return PROTOCOL; }
"TCP"|"ICMP"|"UDP"                                       { yylval.string = copyString(yytext, yyleng); return VAL; }
[a-zA-Z_]+                                               { yylval.string = copyString(yytext, yyleng); return COLUMN; }
\"[^\"]*\"                                               { yylval.string = cutString(yytext, yyleng); return STRING; }
"("                                                      { return LEFT; }
")"                                                      { return RIGHT; }
" "+|\t+|\n+                                             { /* skip whitespaces */ }
%%

YY_BUFFER_STATE get_buf(){
    return YY_CURRENT_BUFFER;
}
