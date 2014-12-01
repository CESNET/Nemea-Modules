#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unirec/unirec.h>
#include "../../unirec/ipaddr.h"

struct ast {
    int type; /*A for AST*/
    int operator; /* 0 - NONE, 1 - OR, 2 - AND */
    struct ast *l;
    struct ast *r;
};

struct expression {
    int type; /* E for Expression */
    char *column;
    int cmp;
/* 0 - ==,
   1 - !=,
   2 - < ,
   3 - <=,
   4 - > ,
   5 - >= */
    int number;
    ur_field_id_t id;
};

struct protocol {
    int type; /* P for Protocol */
    char *data;
    char *cmp;
};

struct ip {
    int type; /* I for Ip */
    char *column;
    int cmp; /* as in struct expression */
    ip_addr_t ipAddr;
    ur_field_id_t id;
};

struct str {
    int type; /* S for String */
    char *column;
    int cmp; /* 0 - ==, 1 - != */
    char *s;
    ur_field_id_t id;
};

struct brack {
    int type; /* B for Bracket */
    struct ast *b;
};

struct ast *newAST(struct ast *l, struct ast *r, int operator)
{
    struct ast *newast = malloc(sizeof(struct ast));
    newast->type = 'A';
    newast->operator = operator;
    newast->l = l;
    newast->r = r;
    return newast;
}

struct ast *newExpression(char *column, char *cmp, int number)
{
    struct expression *newast = malloc(sizeof(struct expression));
    newast->type = 'E';
    newast->column = column;
    newast->number = number;
    if (strcmp(cmp, "==")==0 || strcmp(cmp, "=")==0)
        newast->cmp = 0;
    else if (strcmp(cmp, "!=")==0 || strcmp(cmp, "<>")==0)
        newast->cmp = 1;
    else if (strcmp(cmp, "<")==0)
        newast->cmp = 2;
    else if (strcmp(cmp, "<=")==0 || strcmp(cmp, "=<")==0)
        newast->cmp = 3;
    else if (strcmp(cmp, ">")==0)
        newast->cmp = 4;
    else
        newast->cmp = 5;
    free(cmp);

    newast->id = ur_get_id_by_name(column);
    if (newast->id == UR_INVALID_FIELD)
        printf("Warning: %s is not a valid UniRec field.\n", column);
    return (struct ast *) newast;
}

struct ast *newProtocol(char *cmp, char *data)
{
    struct protocol *newast = malloc(sizeof(struct protocol));
    newast->type = 'P';
    newast->data = data;
    newast->cmp = cmp;
    return (struct ast *) newast;
}

struct ast *newIP(char *column, char *cmp, char *ipAddr)
{
    struct ip *newast = malloc(sizeof(struct ip));
    newast->type = 'I';
    newast->column = column;
    if (strcmp(cmp, "==")==0 || strcmp(cmp, "=")==0)
        newast->cmp = 0;
    else if (strcmp(cmp, "!=")==0 || strcmp(cmp, "<>")==0)
        newast->cmp = 1;
    else if (strcmp(cmp, "<")==0)
        newast->cmp = 2;
    else if (strcmp(cmp, "<=")==0 || strcmp(cmp, "=<")==0)
        newast->cmp = 3;
    else if (strcmp(cmp, ">")==0)
        newast->cmp = 4;
    else
        newast->cmp = 5;
    free(cmp);
    if (!ip_from_str(ipAddr, &(newast->ipAddr)))
        printf("Warning: %s is not a valid IP address.\n", ipAddr);
    newast->id = ur_get_id_by_name(column);
    if (newast->id == UR_INVALID_FIELD)
        printf("Warning: %s is not a valid UniRec field.\n", column);
    if (ur_get_type_by_id(newast->id) != UR_TYPE_IP)
        printf("Warning: Type of %s is not IP address.\n", column);
    return (struct ast *) newast;
}

struct ast *newString(char *column, char *cmp, char *s)
{
    struct str *newast = malloc(sizeof(struct str));
    newast->type = 'S';
    newast->column = column;
    if (strcmp(cmp, "==")==0 || strcmp(cmp, "=")==0)
        newast->cmp = 0;
    else
        newast->cmp = 1;
    free(cmp);
    newast->s = s;
    newast->id = ur_get_id_by_name(column);
    if (newast->id == UR_INVALID_FIELD)
        printf("Warning: %s is not a valid UniRec field.\n", column);
    return (struct ast *) newast;
}

struct ast *newBrack(struct ast *b)
{
    struct brack *newast = malloc(sizeof(struct brack));
    newast->type = 'B';
    newast->b = b;
    return (struct ast *) newast;
}

void printAST(struct ast *ast)
{
    switch (ast->type) {
    case 'A':
        printAST(ast->l);

        if (ast->operator == 1)
            printf(" || ");
        else if (ast->operator == 2)
            printf(" && ");

        if (ast->r)
            printAST(ast->r);
    break;
    case 'E': 
        printf("%s", 
            ((struct expression*) ast)->column); 
       if (((struct ip*) ast)->cmp == 0)
           printf("==");
       else if (((struct ip*) ast)->cmp == 1)
           printf("!=");
       else if (((struct ip*) ast)->cmp == 2)
           printf("<");
       else if (((struct ip*) ast)->cmp == 3)
           printf("<=");
       else if (((struct ip*) ast)->cmp == 4)
           printf(">");
       else if (((struct ip*) ast)->cmp == 5)
           printf(">=");
        printf("%i", 
            ((struct expression*) ast)->number); 
    break;
    case 'P': 
        printf("PROTOCOL%s%s",
            ((struct protocol*) ast)->cmp,
            ((struct protocol*) ast)->data); 
    break;
    case 'I': { 
       char str[46];
       ip_to_str(&(((struct ip*) ast)->ipAddr), str);
       printf("%s", 
            ((struct ip*) ast)->column);
       if (((struct ip*) ast)->cmp == 0)
           printf("==");
       else if (((struct ip*) ast)->cmp == 1)
           printf("!=");
       else if (((struct ip*) ast)->cmp == 2)
           printf("<");
       else if (((struct ip*) ast)->cmp == 3)
           printf("<=");
       else if (((struct ip*) ast)->cmp == 4)
           printf(">");
       else if (((struct ip*) ast)->cmp == 5)
           printf(">=");
       printf("%s",
            str);

    break;
    }
    case 'S': 
       printf("%s", 
            ((struct str*) ast)->column);
       if (((struct str*) ast)->cmp == 0)
           printf("==");
       else
           printf("!="); 
       printf("\"%s\"",
            ((struct str*) ast)->s);
    break;
    case 'B': 
        printf("( "); 
        printAST(((struct brack*) ast)->b);
        printf(" )"); 
    break;
    }

}

void freeAST(struct ast *ast)
{
    if (!ast) return;
    switch (ast->type) {
    case 'A': 
        freeAST(ast->l);
        if (ast->r)
            freeAST(ast->r);
    break;
    case 'E': 
        free(((struct expression*) ast)->column);  
    break;
    case 'P': 
        free(((struct protocol*) ast)->cmp); 
        free(((struct protocol*) ast)->data);
    break;
    case 'I': 
        free(((struct ip*) ast)->column);
        free(&(((struct ip*) ast)->ipAddr));
    break;
    case 'S': 
        free(((struct str*) ast)->column);
        free(((struct str*) ast)->s);
    break;
    case 'B': 
        freeAST(((struct brack*) ast)->b);
    break;
    }
    free(ast);
}

// this compares two numbers
int compareNum(int a, int b, int cmp)
{
    if (a<b && ( cmp==2 || cmp==3 || cmp==1 )) // <, <=, !=
        return 1;
    else if (a>b && ( cmp==4 || cmp==5 || cmp==1 )) // >, >=, !=
        return 1;
    else if (a==b && ( cmp==0 || cmp==3 || cmp==5 )) // ==, <=, >=
        return 1;

    return 0;
}

int evalAST(struct ast *ast, const ur_template_t *in_tmplt, const void *in_rec)
{
    if (!ast) return 0; // NULL
    switch (ast->type) {
    case 'A':
        if (ast->operator == 0)
            return evalAST(ast->l, in_tmplt, in_rec);
        else if (ast->operator == 1)
            return (evalAST(ast->l, in_tmplt, in_rec) || evalAST(ast->r, in_tmplt, in_rec) ? 1 : 0);
        else if (ast->operator == 2)
            return (evalAST(ast->l, in_tmplt, in_rec) && evalAST(ast->r, in_tmplt, in_rec) ? 1 : 0);
    case 'E':  // Expression
        if (((struct expression*) ast)->id == UR_INVALID_FIELD)
            return 0;
        int type = ur_get_type_by_id(((struct expression*) ast)->id);
        if (type == UR_TYPE_UINT8)
            return compareNum(*(uint8_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
        if (type == UR_TYPE_INT8)
            return compareNum(*(int8_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
        if (type == UR_TYPE_INT16)
            return compareNum(*(int16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
        if (type == UR_TYPE_UINT16)
            return compareNum(*(uint16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
        if (type == UR_TYPE_INT32)
            return compareNum(*(int32_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
        if (type == UR_TYPE_UINT32)
            return compareNum(*(uint32_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
        if (type == UR_TYPE_INT64)
            return compareNum(*(int64_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
        if (type == UR_TYPE_UINT64)
            return compareNum(*(uint64_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);

        return 0;
    case 'I': {  //IP address
        if (((struct ip*) ast)->id == UR_INVALID_FIELD)
            return 0;
        int cmp_res = ip_cmp((ip_addr_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct ip*) ast)->id)), &(((struct ip*) ast)->ipAddr));
        int cmp = ((struct ip*) ast)->cmp;
        if (cmp_res == 0) { // Same addresses
            if (cmp == 0 || cmp == 3 || cmp == 5) // ==, <=, >=
                return 1;
            else return 0;
        } else if (cmp_res < 0) { // Address in record is lower than the given one
            if (cmp == 1 || cmp == 2 || cmp == 3) // !=, <, <=
                return 1;
            else return 0;
        } else { // Address in record is higher than the given one
            if (cmp == 1 || cmp == 4 || cmp == 5) // !=, >, >=
                return 1;
            else return 0;
        }
        
    }
    case 'S': { //String
        size_t size = ur_get_dyn_size(in_tmplt, in_rec, ((struct str*) ast)->id);
        char *ret = NULL;
        if (((struct str*) ast)->id == UR_INVALID_FIELD)
            return 0;
        ret = calloc(size+1, sizeof(char));
        strncpy(ret, (char *)(ur_get_dyn(in_tmplt, in_rec, ((struct str*) ast)->id)), size);
        if (strcmp(((struct str*) ast)->s, ret) == 0) { //Same strings
            if ( ((struct str*) ast)->cmp==0 )
                return 1;
            else return 0;
        } else { //Different strings
            if ( ((struct str*) ast)->cmp==1 )
                return 1;
            else return 0;
        }
    }
    case 'B':
        return evalAST(((struct brack*) ast)->b, in_tmplt, in_rec);
    }
}

void changeProtocol(struct ast **ast)
{
    if (!(*ast)) return; // NULL
    switch ((*ast)->type) {
    case 'A':
        changeProtocol(&((*ast)->l));
        changeProtocol(&((*ast)->r));
        return;
    case 'E':
        return;
    case 'P': {
        int protocol;
        if (!strcmp(((struct protocol*) (*ast))->data, "ICMP")) 
            protocol = 1;
        else if (!strcmp(((struct protocol*) (*ast))->data, "TCP")) 
            protocol = 6;
        else if (!strcmp(((struct protocol*) (*ast))->data, "UDP")) 
            protocol = 17;
        char *cmp = ((struct protocol*) (*ast))->cmp;
        free (((struct protocol*) (*ast))->data);
        free (*ast);
        char *retezec = calloc(9, sizeof(char));
        strcpy(retezec, "PROTOCOL");
        *ast = newExpression(retezec, cmp, protocol);
        return;
    }
    case 'I':
        return;
    case 'S':
        return;
    case 'B':
        changeProtocol(&(((struct brack*) (*ast))->b));
        return;
    }
}
