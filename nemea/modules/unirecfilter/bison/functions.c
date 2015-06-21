/**
 * \file unirecfilter.c
 * \brief NEMEA module selecting records and sending specified fields.
 * \author Zdenek Kasner <kasnezde@fit.cvut.cz>
 * \author Klara Drhova <drhovkla@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Vaclav Bartos <washek@cesnet.cz>
 * \date 2013
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2013-2015 CESNET
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../unirecfilter.h"

// get numbers of protocols and services 
#include <netdb.h>

// regexp
#include <sys/types.h>
#include <regex.h>

struct ast *main_tree = NULL;

// prevent warnings
extern struct yy_buffer_state * get_buf();
extern struct yy_buffer_state * yy_scan_string(const char* yy_str);
extern void yy_delete_buffer(struct yy_buffer_state * buffer);

// mapping between strings and enumerated types of operators
typedef struct { char * op_str; cmp_op op_type; } op_pair;

op_pair cmp_op_table[] = { 
   { "==", OP_EQ },
   { "=",  OP_EQ },
   { "!=", OP_NE },
   { "<>", OP_NE },
   { "<",  OP_LT },
   { "<=", OP_LE },
   { ">",  OP_GT },
   { ">=", OP_GE },
   { "=~", OP_RE }
};

cmp_op get_op_type( char* cmp ) {
   size_t table_size = sizeof(cmp_op_table) / sizeof(cmp_op_table[0]);

   for (op_pair *ptr = cmp_op_table; ptr < cmp_op_table + table_size; ptr++)
   {
      if (strcmp(cmp, ptr->op_str) == 0 ) {
         return ptr->op_type;
      }
   }
}

struct ast *newAST(struct ast *l, struct ast *r, int operator)
{
   struct ast *newast = (struct ast *) malloc(sizeof(struct ast));

   newast->type = NODE_T_AST;
   newast->operator = operator;
   newast->l = l;
   newast->r = r;

   return newast;
}

struct ast *newExpression(char *column, char *cmp, int number)
{
   struct expression *newast = (struct expression *) malloc(sizeof(struct expression));

   newast->type = NODE_T_EXPRESSION;
   newast->column = column;
   newast->number = number;
   newast->id = ur_get_id_by_name(column);
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (newast->id == UR_INVALID_FIELD) {
      printf("Warning: %s is not a valid UniRec field.\n", column);
   }
   return (struct ast *) newast;
}

struct ast *newProtocol(char *cmp, char *data)
{
    struct protocol *newast = (struct protocol *) malloc(sizeof(struct protocol));
    newast->type = NODE_T_PROTOCOL;
    newast->data = data;
    newast->cmp = cmp;
    return (struct ast *) newast;
}

struct ast *newIP(char *column, char *cmp, char *ipAddr)
{
   struct ip *newast = (struct ip *) malloc(sizeof(struct ip));
   newast->type = NODE_T_IP;
   newast->column = column;
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (!ip_from_str(ipAddr, &(newast->ipAddr))) {
      printf("Warning: %s is not a valid IP address.\n", ipAddr);
   }
   free(ipAddr);

   newast->id = ur_get_id_by_name(column);
   if (newast->id == UR_INVALID_FIELD) {
      printf("Warning: %s is not a valid UniRec field.\n", column);
   }
   if (ur_get_type_by_id(newast->id) != UR_TYPE_IP) {
      printf("Warning: Type of %s is not IP address.\n", column);
   }
   return (struct ast *) newast;
}

struct ast *newString(char *column, char *cmp, char *s)
{
   int retval;
   char errb[1024];
   errb[1023] = 0;
   struct str *newast = (struct str *) malloc(sizeof(struct str));
   newast->type = NODE_T_STRING;
   newast->column = column;

   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (newast->cmp == OP_RE) {
      newast->s = strdup(s);
      if ((retval = regcomp(&newast->re, s, REG_EXTENDED)) != 0) {
         regerror(retval, &newast->re, errb, 1023);
         printf("Regexp error: %s\n", errb);
         regfree(&newast->re);
      }
      free(s);
   } else {
      newast->s = s;
   }
   newast->id = ur_get_id_by_name(column);
   if (newast->id == UR_INVALID_FIELD) {
      printf("Warning: %s is not a valid UniRec field.\n", column);
   }
   return (struct ast *) newast;
}

struct ast *newBrack(struct ast *b)
{
   struct brack *newast = (struct brack *) malloc(sizeof(struct brack));
   newast->type = NODE_T_BRACKET;
   newast->b = b;
   return (struct ast *) newast;
}

void printAST(struct ast *ast)
{
   if (ast == NULL) {
      puts("No syntax tree for printing");
      return;
   }
   switch (ast->type) {
   case NODE_T_AST:
      printAST(ast->l);

      if (ast->operator == 1) {
         printf(" || ");
      } else if (ast->operator == 2) {
         printf(" && ");
      }
      if (ast->r) {
         printAST(ast->r);
      }
      break;
   case NODE_T_EXPRESSION:
      printf("%s", ((struct expression*) ast)->column);

      switch (((struct ip*) ast)->cmp) {
      case (OP_EQ):
         printf(" == ");
         break;
      case (OP_NE):
         printf(" != ");
         break;
      case (OP_LT):
         printf(" < ");
         break;
      case (OP_LE):
         printf(" <= ");
         break;
      case (OP_GT):
         printf(" > ");
         break;
      case (OP_GE):
         printf(" >= ");
         break;
      case (OP_RE):
         printf(" =~ ");
         break;
      default:
         printf(" <invalid operator> ");
      }
      printf("%i", ((struct expression*) ast)->number);
      break;
   case NODE_T_PROTOCOL:
      printf("PROTOCOL %s %s",
            ((struct protocol*) ast)->cmp,
            ((struct protocol*) ast)->data);
      break;
   case NODE_T_IP: {
      char str[46];
      ip_to_str(&(((struct ip*) ast)->ipAddr), str);
      
      printf("%s", 
            ((struct ip*) ast)->column);

      switch (((struct ip*) ast)->cmp) {
      case (OP_EQ):
         printf(" == ");
         break;
      case (OP_NE):
         printf(" != ");
         break;
      case (OP_LT):
         printf(" < ");
         break;
      case (OP_LE):
         printf(" <= ");
         break;
      case (OP_GT):
         printf(" > ");
         break;
      case (OP_GE):
         printf(" >= ");
         break;
      default:
         printf(" <invalid operator> ");
      }
      printf("%s", str);

      break;
      }
   case NODE_T_STRING:
      printf("%s", ((struct str*) ast)->column);
      switch (((struct ip*) ast)->cmp) {
      case (OP_EQ):
         printf(" == ");
         break;
      case (OP_NE):
         printf(" != ");
         break;
      case (OP_RE):
         printf(" =~ ");
         break;
      default:
         printf(" <invalid operator> ");
      }
      printf("\"%s\"", ((struct str*) ast)->s);
      break;
   case NODE_T_BRACKET:
      printf("( ");
      printAST(((struct brack*) ast)->b);
      printf(" )");
      break;
   }

}

void freeAST(struct ast *ast)
{
   if (!ast) {
      return;
   }
   switch (ast->type) {
   case NODE_T_AST:
      freeAST(ast->l);
      if (ast->r) {
         freeAST(ast->r);
      }
      break;
   case NODE_T_EXPRESSION:
      free(((struct expression*) ast)->column);
      break;
   case NODE_T_PROTOCOL:
      free(((struct protocol*) ast)->cmp);
      free(((struct protocol*) ast)->data);
      break;
   case NODE_T_IP:
      free(((struct ip*) ast)->column);
      // free(&(((struct ip*) ast)->ipAddr));
      break;
   case NODE_T_STRING:
      free(((struct str*) ast)->column);
      free(((struct str*) ast)->s);
      ((struct str*) ast)->s = NULL;
      regfree(&((struct str*) ast)->re);
      break;
   case NODE_T_BRACKET:
      freeAST(((struct brack*) ast)->b);
      break;
   }
   free(ast);
}

// compares two numbers
int compareNum(int a, int b, cmp_op op)
{
   switch (op) {
      case OP_LE: 
         return a <= b;
      case OP_LT: 
         return a < b;
      case OP_NE: 
         return a != b;
      case OP_GE: 
         return a >= b;
      case OP_GT: 
         return a > b;
      case OP_EQ: 
         return a == b;
   }
   return 0;
}

int evalAST(struct ast *ast, const ur_template_t *in_tmplt, const void *in_rec)
{
   size_t size;
   char *expr;
   int ret;
   if (!ast) {
      return 0; // NULL
   }
   switch (ast->type) {
   case NODE_T_AST:
      if (ast->operator == 0) {
         return evalAST(ast->l, in_tmplt, in_rec);
      } else if (ast->operator == 1) {
         return (evalAST(ast->l, in_tmplt, in_rec) || evalAST(ast->r, in_tmplt, in_rec) ? 1 : 0);
      } else if (ast->operator == 2) {
         return (evalAST(ast->l, in_tmplt, in_rec) && evalAST(ast->r, in_tmplt, in_rec) ? 1 : 0);
      }
   case NODE_T_EXPRESSION:
      if (((struct expression*) ast)->id == UR_INVALID_FIELD) {
         return 0;
      }
      int type = ur_get_type_by_id(((struct expression*) ast)->id);
      switch (type) {
      case UR_TYPE_UINT8:
         return compareNum(*(uint8_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT8:
         return compareNum(*(int8_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT16:
         return compareNum(*(int16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_UINT16:
         return compareNum(*(uint16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT32:
         return compareNum(*(int32_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_UINT32:
         return compareNum(*(uint32_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT64:
         return compareNum(*(int64_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_UINT64:
         return compareNum(*(uint64_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      }

      return 0;
   case NODE_T_IP:
      if (((struct ip*) ast)->id == UR_INVALID_FIELD) {
         return 0;
      }
      int cmp_res = ip_cmp((ip_addr_t *) (ur_get_ptr_by_id(in_tmplt, in_rec, ((struct ip*) ast)->id)), &(((struct ip*) ast)->ipAddr));
      cmp_op cmp = ((struct ip*) ast)->cmp;

      if (cmp_res == 0) { 
      // Same addresses
         return cmp == OP_EQ || cmp == OP_LE || cmp == OP_GE;
      } else if (cmp_res < 0) {
       // Address in record is lower than the given one
         return cmp == OP_NE || cmp == OP_LT || cmp == OP_LE;
      } else {
      // Address in record is higher than the given one
         return cmp == OP_NE || cmp == OP_GT || cmp == OP_GE;
      }

   case NODE_T_STRING:
      size = ur_get_dyn_size(in_tmplt, in_rec, ((struct str*) ast)->id);
      expr = (char *)(ur_get_dyn(in_tmplt, in_rec, ((struct str*) ast)->id));

      if (((struct str*) ast)->id == UR_INVALID_FIELD) {
         return 0;
      }
      if (((struct str*) ast)->cmp == OP_RE) {

         memcpy(str_buffer, expr, size);
         str_buffer[size] = '\0';

         if (regexec(&((struct str*) ast)->re, str_buffer, 0, NULL, 0) == REG_NOMATCH) {
            // string does not match regular expression
            return 0;
         } else {
            // match
            return 1;
         }
      } else {
         // strings are different in size/content (size comparisson necessary for zero-sized strings)
         if (strlen(((struct str*) ast)->s) != size || strncmp(((struct str*) ast)->s, expr, size) != 0) {
            ret = 0;
         } else {
            ret = 1;
         }
         if ( ((struct str*) ast)->cmp == OP_EQ) {
            // return for equality operator
            return ret;
         } else {
            // return for non-equality operator
            return !ret;
         }
      }
   case NODE_T_BRACKET:
      return evalAST(((struct brack*) ast)->b, in_tmplt, in_rec);
   }
}

void changeProtocol(struct ast **ast)
{
   int protocol;
   struct protoent *proto = NULL;
   char *cmp, *retezec;
   
   if (!(*ast)) {
      return; // NULL
   }

   switch ((*ast)->type) {
   case NODE_T_AST:
      changeProtocol(&((*ast)->l));
      changeProtocol(&((*ast)->r));
      return;
   case NODE_T_EXPRESSION:
      return;
   case NODE_T_PROTOCOL:
      proto = getprotobyname(((struct protocol*) (*ast))->data);
      if (proto != NULL) {
         protocol = proto->p_proto;
      } else {
         fprintf(stderr, "Error: Protocol %s is not known, revisit /etc/protocols.\n", (((struct protocol *) (*ast))->data));
      }
      cmp = ((struct protocol*) (*ast))->cmp;
      free(((struct protocol*) (*ast))->data);
      free(*ast);
      retezec = calloc(9, sizeof(char));
      strcpy(retezec, "PROTOCOL");
      *ast = newExpression(retezec, cmp, protocol);
      return;
   case NODE_T_IP:
      return;
   case NODE_T_STRING:
      return;
   case NODE_T_BRACKET:
      changeProtocol(&(((struct brack*) (*ast))->b));
      return;
   }
}

/**
 * \brief Get Abstract syntax tree from filter
 * \param[in] str is in following format: "<filter>"
 * \return pointer to abstract syntax tree
 */
 
struct ast *getTree(const char *str)
{
   struct ast *result;
   if (str == NULL || str[0] == '\0') {
      printf("No Filter.\n");
      return NULL;
   }
   yy_scan_string(str);

   if (yyparse()) {        // failure
      result = NULL;
   } else {
      result = main_tree;  // success
   }
   yy_delete_buffer(get_buf());

   printf("Filter: ");
   printAST(result);
   printf("\n");

   return result;
}

