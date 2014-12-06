%{
    #include <stdio.h>
    /* functions definition */
    struct ast *newAST(struct ast *l, struct ast *r, int operator);
    struct ast *newExpression(char *column, char *cmp, int number);
    struct ast *newIP(char *column, char *cmp, char *ip);
    struct ast *newString(char *column, char *cmp, char *s);
    struct ast *newProtocol(char *cmp, char *data);
    struct ast *newBrack(struct ast *b);

    void printAST(struct ast *ast);
    void freeAST(struct ast *ast);
    int evalAST(struct ast *ast);
    void changeProtocol(struct ast **ast);

    void yyerror(char *errmsg)
    {
        fprintf(stderr, "%s\n", errmsg);    
    }
%}

%union {
    char *string;
    int number;
    struct ast* ast;
}

%token <number> NUMBER
%token <string> COLUMN
%token <string> EQ
%token <string> CMP
%token <number> OPERATOR
%token <string> VAL
%token <string> IP
%token <string> STRING
%token LEFT RIGHT PROTOCOL
%token END

%type <ast> exp explist
%%

explist: END { return 0; }
    | exp { $$ = newAST($1, NULL, 0); }
    | explist OPERATOR exp { $$ = newAST($1, $3, $2); }
    | explist OPERATOR LEFT explist RIGHT { $$ = newAST($1, (struct ast *) newBrack($4), $2); }
    | LEFT explist RIGHT { $$ = (struct ast *) newBrack($2); }
    | explist END { /*printAST($$); printf("\n");*/ changeProtocol(&$$); return (int) $$;}
    ;
 
exp:
    COLUMN CMP NUMBER { $$ = newExpression($1, $2, $3); }
    | PROTOCOL EQ VAL { $$ = (struct ast *) newProtocol($2, $3); }
    | PROTOCOL EQ STRING { $$ = (struct ast *) newProtocol($2, $3); }
    | COLUMN EQ IP { $$ = (struct ast *) newIP($1, $2, $3); }
    | COLUMN CMP IP { $$ = (struct ast *) newIP($1, $2, $3); }
    | COLUMN EQ STRING { $$ = (struct ast *) newString($1, $2, $3); }
    | COLUMN EQ NUMBER { $$ = newExpression($1, $2, $3); }
    ;

%%


