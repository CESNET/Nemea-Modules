%{
    //#define YYDEBUG 1
    #include <stdio.h>
    #include <stdlib.h>
    #include "functions.h"

    extern struct ast *main_tree;

    /* functions definition */
    struct ast *newAST(struct ast *l, struct ast *r, log_op operator);
    struct ast *newBoolean(char *value);
    struct ast *newExpression(char *column, char *cmp, int64_t number, int is_signed);
    struct ast *newExpressionPort(char *cmp, uint64_t number);
    struct ast *newExpressionFP(char *column, char *cmp, double number);
    struct ast *newExpressionDateTime(char *column, char *cmp, char *datetime);
    struct ast *newExpressionArray(char *column, char *cmp, char *array);
    struct ast *newIP(char *column, char *cmp, char *ip);
    struct ast *newIPNET(char *column, char *cmp, char *ipAddr);
    struct ast *newString(char *column, char *cmp, char *s);
    struct ast *newProtocol(char *cmp, char *data);
    struct ast *newBrack(struct ast *b);
    struct ast *newNegation(struct ast *b);

    void yyerror(const char *errmsg) {
        fprintf(stderr, "Parsing error: %s\n", errmsg);
    }
%}

%union {
    char *string;
    int64_t number;
    double floating;
    struct ast* ast;
}

%token <number> SIGNED
%token <number> UNSIGNED
%token <floating> FLOAT
%token <string> COLUMN
%token <string> EQ
%token <string> CMP
%token <string> REGEX
%token <string> PROTO_NAME
%token <string> IP
%token <string> DATETIME
%token <string> ARRAY
%token <string> STRING
%token <string> NET
%token <string> BOOLEAN
%token PORT
%token HOST
%token AND OR
%token LEFT RIGHT PROTOCOL
%token END

%right OR
%right AND
%right NOT

%type <ast> exp explist
%start body
%%

body: /* empty */
    | explist { changeProtocol(&$1); main_tree = $1; }
    ;

explist:
    exp { $$ = newAST($1, NULL, OP_NOP); }
    | explist AND exp { $$ = newAST($1, $3, OP_AND); }
    | explist OR exp { $$ = newAST($1, $3, OP_OR); }
    ;
 
exp:
    COLUMN CMP SIGNED { $$ = newExpression($1, $2, $3, 1); }
    | COLUMN CMP UNSIGNED { $$ = newExpression($1, $2, $3, 0); }
    | COLUMN CMP FLOAT { $$ = newExpressionFP($1, $2, $3); }
    | COLUMN CMP DATETIME { $$ = newExpressionDateTime($1, $2, $3); }
    | COLUMN EQ DATETIME { $$ = newExpressionDateTime($1, $2, $3); }
    | COLUMN CMP ARRAY { $$ = newExpressionArray($1, $2, $3); if ($$ == NULL) {YYERROR;}}
    | HOST CMP ARRAY { $$ = newExpressionArray(strdup("host"), $2, $3); if ($$ == NULL) {YYERROR;}}
    | PORT CMP ARRAY { $$ = newExpressionArray(strdup("port"), $2, $3); if ($$ == NULL) {YYERROR;}}
    | PROTOCOL CMP UNSIGNED { $$ = newExpression(strdup("PROTOCOL"), $2, $3, 0); }
    | PROTOCOL EQ UNSIGNED { $$ = newExpression(strdup("PROTOCOL"), $2, $3, 0); }
    | PROTOCOL EQ PROTO_NAME { $$ = (struct ast *) newProtocol($2, $3); }
    | PROTOCOL EQ STRING { $$ = (struct ast *) newProtocol($2, $3); }
    | COLUMN EQ IP { $$ = (struct ast *) newIP($1, $2, $3); }
    | COLUMN EQ NET { $$ = (struct ast *) newIPNET($1, $2, $3); }
    | COLUMN CMP IP { $$ = (struct ast *) newIP($1, $2, $3); }
    | COLUMN CMP NET { $$ = (struct ast *) newIPNET($1, $2, $3); }
    | HOST EQ IP { $$ = (struct ast *) newIP(strdup("host"), $2, $3); }
    | HOST EQ NET { $$ = (struct ast *) newIPNET(strdup("host"), $2, $3); }
    | HOST CMP IP { $$ = (struct ast *) newIP(strdup("host"), $2, $3); }
    | HOST CMP NET { $$ = (struct ast *) newIPNET(strdup("host"), $2, $3); }
    | COLUMN EQ STRING { $$ = (struct ast *) newString($1, $2, $3); }
    | COLUMN REGEX STRING { $$ = (struct ast *) newString($1, $2, $3); }
    | COLUMN EQ SIGNED { $$ = newExpression($1, $2, $3, 1); }
    | COLUMN EQ UNSIGNED { $$ = newExpression($1, $2, $3, 0); }
    | COLUMN EQ FLOAT { $$ = newExpressionFP($1, $2, $3); }
    | PORT CMP UNSIGNED { $$ = newExpressionPort($2, $3); }
    | PORT EQ UNSIGNED { $$ = newExpressionPort($2, $3); }
    | NOT explist {$$ = (struct ast *) newNegation($2);}
    | LEFT explist RIGHT { $$ = (struct ast *) newBrack($2); }
    | BOOLEAN { $$ = (struct ast *) newBoolean($1); }
    ;

%%


