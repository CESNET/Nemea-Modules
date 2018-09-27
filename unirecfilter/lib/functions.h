/**
 * \file functions.h
 * \brief NEMEA library for matching UniRec
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

#ifndef LIB_UNIREC_FUNCTIONS_H
#define LIB_UNIREC_FUNCTIONS_H

#include <unirec/unirec.h>
#include <sys/types.h>
#include <regex.h>

#define DYN_FIELD_MAX_SIZE 1024 // Maximal size of dynamic field, longer fields will be cutted to this size

#define SET_NULL(field_id, tmpl, data) \
memset(ur_get_ptr_by_id(tmpl, data, field_id), 0, ur_get_size(field_id));

/* Used for types of expression nodes in abstract syntax tree */
typedef enum { NODE_T_AST, NODE_T_EXPRESSION, NODE_T_EXPRESSION_FP,
               NODE_T_EXPRESSION_DATETIME, NODE_T_PROTOCOL, NODE_T_IP, NODE_T_NET, NODE_T_STRING,
               NODE_T_BRACKET, NODE_T_NEGATION } node_type;

/* Used for describing comparison operators */
typedef enum { OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_RE /* regex match */, OP_INVALID } cmp_op;

/* Used for describing logical operators */
typedef enum { OP_AND, OP_OR, OP_NOP } log_op;


/* AST nodes */
struct ast {
   node_type type;
   log_op operator;
   struct ast *l;
   struct ast *r;
};

struct expression {
   node_type type;
   cmp_op cmp;
   char *column;
   int64_t number;
   ur_field_id_t id;
   int is_signed;
};

struct expression_fp {
   node_type type;
   cmp_op cmp;
   char *column;
   double number;
   ur_field_id_t id;
};

struct expression_datetime {
   node_type type;
   cmp_op cmp;
   char *column;
   ur_time_t date;
   ur_field_id_t id;
};

struct protocol {
   node_type type;
   char *data;
   char *cmp;
};

struct ip {
   node_type type;
   cmp_op cmp;
   char *column;
   ip_addr_t ipAddr;
   ur_field_id_t id;
};

struct ipnet {
   node_type type;
   cmp_op cmp;
   char *column;
   ip_addr_t ipAddr;
   ip_addr_t ipMask;
   uint8_t mask;
   ur_field_id_t id;
};

struct str {
   node_type type;
   cmp_op cmp;
   char *column;
   char *s;
   regex_t re;
   ur_field_id_t id;
};

struct brack {
   node_type type;
   struct ast *b;
};

int yylex();
int yyparse();
void printAST(struct ast *ast);
int evalAST(struct ast *ast, const ur_template_t *in_tmplt, const void *in_rec);
void freeAST(struct ast *tree);
struct ast *getTree(const char *str, const char *port_number);
void changeProtocol(struct ast **ast);

char * str_buffer;

#endif /* LIB_UNIREC_FUNCTIONS_H */

