%option noyywrap warn nounput case-insensitive

%{
    #include "parser.tab.h"
    #include <string.h>

    #define YY_NO_INPUT

    char *copyString(char* str, int len) {
        char *ret = calloc(len+1, sizeof(char));
        strcpy(ret, str);
        return ret;
    }
    char *cutString(char* str, int len) {
        char *ret = calloc(len-1, sizeof(char));
        strncpy(ret, str+1, (size_t)len-2);
        return ret;
    }
%}

dec-octet     [0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]
IPv4          {dec-octet}\.{dec-octet}\.{dec-octet}\.{dec-octet}

h16     [0-9A-Fa-f]{1,4}
ls32    {h16}:{h16}|{IPv4}
IPv6    ({h16}:){6}{ls32}|::({h16}:){5}{ls32}|({h16})?::({h16}:){4}{ls32}|(({h16}:){0,1}{h16})?::({h16}:){3}{ls32}|(({h16}:){0,2}{h16})?::({h16}:){2}{ls32}|(({h16}:){0,3}{h16})?::{h16}:{ls32}|(({h16}:){0,4}{h16})?::{ls32}|(({h16}:){0,5}{h16})?::{h16}|(({h16}:){0,6}{h16})?::

%%

">"|"<"|"=<"|"<="|">="|"=>"                              { yylval.string = copyString(yytext, yyleng); return CMP; }
"="|"=="|"!="|"<>"                                       { yylval.string = copyString(yytext, yyleng); return EQ; }
"=~"|"~="                                                { yylval.string = copyString(yytext, yyleng); return REGEX; }
"!"|"NOT"                                                { return NOT; }
"||"|"OR"                                                { return OR; }
"&&"|"AND"                                               { return AND; }
-?[0-9]+\.[0-9]+                                         { sscanf(yytext, "%lf", &yylval.floating); return FLOAT; }
-[0-9]+                                                  { sscanf(yytext, "%" SCNi64, &yylval.number); return SIGNED; }
[0-9]+                                                   { sscanf(yytext, "%" SCNi64, &yylval.number); return UNSIGNED; }
{IPv4}                                                   { yylval.string = copyString(yytext, yyleng); return IP; }
\"?{IPv6}\"?                                             { yylval.string = cutString(yytext, yyleng); return IP; }
"PROTOCOL"                                               { return PROTOCOL; }
"TCP"|"ICMP"|"UDP"                                       { yylval.string = copyString(yytext, yyleng); return PROTO_NAME; }
[a-zA-Z_]+                                               { yylval.string = copyString(yytext, yyleng); return COLUMN; }
\"(\\.|[^"])*\"                                          { yylval.string = cutString(yytext, yyleng); return STRING; }
'(\\.|[^"])*'                                            { yylval.string = cutString(yytext, yyleng); return STRING; }
"("                                                      { return LEFT; }
")"                                                      { return RIGHT; }
" "+|\t+|\n+                                             { /* skip whitespaces */ }
%%

YY_BUFFER_STATE get_buf(){
    return YY_CURRENT_BUFFER;
}
