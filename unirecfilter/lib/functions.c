/**
 * \file functions.c
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "functions.h"

// get numbers of protocols and services
#include <netdb.h>
// formatting uint64_t and int64_t
#include <inttypes.h>
#define __STDC_FORMAT_MACROS
// regexp
#include <sys/types.h>
#include <regex.h>
#include "fields.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_RESET   "\x1b[0m"

struct ast *main_tree = NULL;

// prevent warnings
extern struct yy_buffer_state * get_buf();
extern struct yy_buffer_state * yy_scan_string(const char* yy_str);
extern void yy_delete_buffer(struct yy_buffer_state * buffer);
char *str_buffer;

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
   { "=~", OP_RE },
   { "IN", OP_IN },
   { "in", OP_IN },
   { "~=", OP_RE }
};

/**
 * Apply netmask mask to an IP address in tg_ip.
 *
 * \param[in,out] tg_ip pointer to IP address that will be masked (binary and with mask)
 * \param[in] mask   pointer to netmask (32 resp. 128 bits of leading ones and trailing zeros) created by ip_make_mask()
 */
void ip_mask(ip_addr_t *tg_ip, ip_addr_t *mask)
{
   if (ip_is4(tg_ip)) {
      tg_ip->ui64[0] = 0;
      tg_ip->ui32[2] &= mask->ui32[2];
      tg_ip->ui32[3] = 0xFFFFFFFF;
   } else {
      tg_ip->ui64[0] &= mask->ui64[0];
      tg_ip->ui64[1] &= mask->ui64[1];
   }
}

/**
 * Create a netmask with mbits leading '1' bits into tg_ip.
 *
 * \param[in,out] tg_ip Pointer to an IP address (IPv4 or IPv6) that will be converted into netmask (binary & with mask). The IP must be set in advance in order to distinguish IPv4 and IPv6.
 * \param[in] mbits   Number of leading ones ('1') in the netmask, it must be lower than 32 resp. 128 bits for IPv4 resp. IPv6.
 */
void ip_make_mask(ip_addr_t *tg_ip, uint8_t mbits)
{
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#define IP4BITMASK(n) (n == 0 ? 0 : ntohl(-1 << (32 - n)))
#define IP6HBITMASK(n) (n == 0 ? 0LL : ntohll(-1LL << (64 - n)))
   if (ip_is4(tg_ip)) {
      tg_ip->ui32[2] = IP4BITMASK(mbits);
   } else {
      if (mbits > 64) {
         tg_ip->ui64[0] = 0xFFFFFFFFFFFFFFFFULL;
         tg_ip->ui64[1] = IP6HBITMASK(mbits - 64);
      } else {
         tg_ip->ui64[0] = IP6HBITMASK(mbits);
         tg_ip->ui64[1] = 0ULL;
      }
   }
}

cmp_op get_op_type(char *cmp) {
   size_t table_size = sizeof(cmp_op_table) / sizeof(cmp_op_table[0]);

   for (op_pair *ptr = cmp_op_table; ptr < cmp_op_table + table_size; ptr++)
   {
      if (strcmp(cmp, ptr->op_str) == 0 ) {
         return ptr->op_type;
      }
   }
   fprintf(stderr, "Error: Operator not recognized.\n");
   return OP_INVALID;
}

struct ast *newAST(struct ast *l, struct ast *r, log_op operator)
{
   struct ast *newast = (struct ast *) malloc(sizeof(struct ast));

   newast->type = NODE_T_AST;
   newast->operator = operator;
   newast->l = l;
   newast->r = r;

   return newast;
}
struct ast *newBoolean(char *value)
{
   struct boolean *newast = (struct boolean *) malloc(sizeof(struct boolean));
   newast->type = NODE_T_BOOLEAN;
   if (strcasecmp(value, "true") == 0) {
      newast->value = 1;
   } else {
      newast->value = 0;
   }
   return (struct ast *) newast;
}

struct ast *newExpression(char *column, char *cmp, int64_t number, int is_signed)
{
   struct expression *newast = (struct expression *) malloc(sizeof(struct expression));

   newast->type = NODE_T_EXPRESSION;
   newast->column = column;
   newast->number = number;
   int id = ur_get_id_by_name(column);
   newast->is_signed = is_signed;
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (id == UR_E_INVALID_NAME) {
      printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
      newast->id = UR_INVALID_FIELD;
   } else if (ur_get_type(id) != UR_TYPE_INT8 &&
            ur_get_type(id) != UR_TYPE_UINT8 &&
            ur_get_type(id) != UR_TYPE_INT16 &&
            ur_get_type(id) != UR_TYPE_UINT16 &&
            ur_get_type(id) != UR_TYPE_INT32 &&
            ur_get_type(id) != UR_TYPE_UINT32 &&
            ur_get_type(id) != UR_TYPE_INT64 &&
            ur_get_type(id) != UR_TYPE_UINT64) {
      if (ur_get_type(id) == UR_TYPE_TIME) {
         printf("Error: %s is ur_time_t, date&time is expected in comparison (Format: YYYY-mm-ddTHH:MM:SS.sss, where .sss is optional). Corresponding rule will always evaluate false.\n", column);
      } else {
         printf("Error: Type of %s is not integer. Corresponding rule will always evaluate false.\n", column);
      }
      newast->id = UR_INVALID_FIELD;
   } else {
      newast->id = id;
   }
   return (struct ast *) newast;
}

struct ast *newExpressionPort(char *cmp, uint64_t number)
{
   int id;
   struct expression_port *newast = (struct expression_port *) malloc(sizeof(struct expression_port));

   newast->type = NODE_T_EXPRESSION_PORT;
   newast->number = number;
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (newast->number > 65535) {
      printf("Warning: port is only 16b field but a value bigger than 65535 was given. This can work badly.\n");
   }

   id = ur_get_id_by_name("SRC_PORT");
   if (id == UR_E_INVALID_NAME) {
      printf("Warning: SRC_PORT is not present in input format. Corresponding rule will always evaluate false.\n");
      newast->srcport = UR_INVALID_FIELD;
   } else if (ur_get_type(id) != UR_TYPE_UINT16) {
      printf("Error: Type of SRC_PORT is not integer. Corresponding rule will always evaluate false.\n");
      newast->srcport = UR_INVALID_FIELD;
   } else {
      newast->srcport = id;
   }
   id = ur_get_id_by_name("DST_PORT");
   if (id == UR_E_INVALID_NAME) {
      printf("Warning: DST_PORT is not present in input format. Corresponding rule will always evaluate false.\n");
      newast->dstport = UR_INVALID_FIELD;
   } else if (ur_get_type(id) != UR_TYPE_UINT16) {
      printf("Error: Type of DST_PORT is not integer. Corresponding rule will always evaluate false.\n");
      newast->dstport = UR_INVALID_FIELD;
   } else {
      newast->dstport = id;
   }
   return (struct ast *) newast;
}

struct ast *newExpressionFP(char *column, char *cmp, double number)
{
   struct expression_fp *newast = (struct expression_fp *) malloc(sizeof(struct expression_fp));

   newast->type = NODE_T_EXPRESSION_FP;
   newast->column = column;
   newast->number = number;
   int id = ur_get_id_by_name(column);
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (id == UR_E_INVALID_NAME) {
      printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
      newast->id = UR_INVALID_FIELD;
   } else if (ur_get_type(id) != UR_TYPE_FLOAT &&
            ur_get_type(id) != UR_TYPE_DOUBLE) {
     printf("Warning: Type of %s is not float. Corresponding rule will always evaluate false.\n", column);
     newast->id = UR_INVALID_FIELD;
   } else {
      newast->id = id;
   }
   return (struct ast *) newast;
}

struct ast *newExpressionDateTime(char *column, char *cmp, char *datetime)
{
   struct expression_datetime *newast = (struct expression_datetime *) malloc(sizeof(struct expression_datetime));

   newast->type = NODE_T_EXPRESSION_DATETIME;
   newast->column = column;

   int id = ur_get_id_by_name(column);
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (id == UR_E_INVALID_NAME) {
      printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
      newast->id = UR_INVALID_FIELD;
   } else if (ur_get_type(id) != UR_TYPE_TIME) {
     printf("Warning: Type of %s is not UR_TIME. Corresponding rule will always evaluate false.\n", column);
     newast->id = UR_INVALID_FIELD;
   } else {
      newast->id = id;
   }

   if (ur_time_from_string(&newast->date, datetime) != 0) {
      printf("Error: %s could not be loaded. Expected format: YYYY-mm-ddTHH:MM:SS.sss, where .sss is optional. Eg. 2018-06-27T19:44:41.123.\n", datetime);
      newast->id = UR_INVALID_FIELD;
   }
   free(datetime);
   return (struct ast *) newast;
}

static int compareUI64(const void *p1, const void *p2)
{
   if ((*(uint64_t *) p1) == (*(uint64_t *) p2)) {
      return 0;
   } else if ((*(uint64_t *) p1) > (*(uint64_t *) p2)) {
      return 1;
   } else {
      return -1;
   }
}

static int compareI64(const void *p1, const void *p2)
{
   return ((*(int64_t *) p1) - (*(int64_t *) p2));
}

static int compareDouble(const void *p1, const void *p2)
{
   double EPS = 1e-8;
   double res = ((*(double *) p1) - (*(double *) p2));
   if ((res < 0 ? -res : res) < EPS) {
      return 0;
   } else {
      return res < 0 ? -1 : 1;
   }
}

static int compareIPs(const void *p1, const void *p2)
{

   if (ip_is4(&((const struct ipprefix *) p1)->ip) && ip_is6(&((const struct ipprefix *) p2)->ip)) {
      return -1;
   } else if (ip_is6(&((const struct ipprefix *) p1)->ip) && ip_is4(&((const struct ipprefix *) p2)->ip)) {
      return 1;
   }

   return ip_cmp(&((const struct ipprefix *) p1)->ip, &((const struct ipprefix *) p2)->ip);
}

static int compareIPwithPrefix(const void *p1, const void *p2)
{
   struct ipprefix *stack = (struct ipprefix *) p2;
   ip_addr_t needle = ((struct ipprefix *) p1)->ip;

   if (ip_is4(&needle) && ip_is6(&stack->ip)) {
      return -1;
   } else if (ip_is6(&needle) && ip_is4(&stack->ip)) {
      return 1;
   }

   ip_mask(&needle, &stack->mask);

   return ip_cmp(&needle, &stack->ip);
}

struct ast *newExpressionArray(char *column, char *cmp, char *array)
{
   int i, id, iddst, host = 0;
   struct expression_array *newast = (struct expression_array *) malloc(sizeof(struct expression_array));

   /* init all arrays, one will be allocated: */
   newast->array_values = 0;
   newast->array_values_ipprefix = 0;
   newast->array_values_date = 0;
   newast->array_values_double = 0;

   newast->id = UR_INVALID_FIELD;
   newast->dstid = UR_INVALID_FIELD;

   newast->type = NODE_T_EXPRESSION_ARRAY;
   newast->column = column;
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (strcmp(column, "host") == 0) {
      id = ur_get_id_by_name("SRC_IP");
      iddst = ur_get_id_by_name("DST_IP");
      host = 1;
   } else if (strcmp(column, "port") == 0) {
      id = ur_get_id_by_name("SRC_PORT");
      iddst = ur_get_id_by_name("DST_PORT");
      host = 1;
   } else {
      id = ur_get_id_by_name(column);
   }

   if (id == UR_E_INVALID_NAME) {
      printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
   } else {
      newast->id = id;
   }
   newast->field_type = ur_get_type(id);

   if (host == 1) {
      if (iddst == UR_E_INVALID_NAME) {
         printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
      } else {
         newast->dstid = iddst;
      }
   }

   newast->array_size = 0;
   newast->array_values = 0;

   char *p = array;
   int strsize = strlen(array);
   for (i = 0; i < strsize; i++) {
      if (array[i] == ',') {
         newast->array_size++;
         array[i] = 0;
      }
   }
   if (i != 0) {
      newast->array_size++;
   }

   char is_unsigned_int = 0;
   switch (newast->field_type) {
   case UR_TYPE_UINT8:
   case UR_TYPE_UINT16:
   case UR_TYPE_UINT32:
   case UR_TYPE_UINT64:
      is_unsigned_int = 1;
   case UR_TYPE_INT8:
   case UR_TYPE_INT16:
   case UR_TYPE_INT32:
   case UR_TYPE_INT64:
      newast->array_values = calloc(newast->array_size, sizeof(uint64_t));
      for (int i=0; i < newast->array_size; i++) {
         if (is_unsigned_int == 1) {
            if (sscanf(p, "%"SCNu64, &newast->array_values[i]) != 1) {
               /* error */
               printf("Error: %s could not be parsed.\n", p);
               free(newast->array_values);
               newast->array_values = 0;
               goto parsing_error;
            }
         } else {
            if (sscanf(p, "%"SCNi64, &newast->array_values[i]) != 1) {
               /* error */
               printf("Error: %s could not be parsed.\n", p);
               free(newast->array_values);
               newast->array_values = 0;
               goto parsing_error;
            }
         }
         p += strlen(p) + 1;
      }
      if (is_unsigned_int == 1) {
         qsort(newast->array_values, newast->array_size, sizeof(uint64_t), compareUI64);
      } else {
         qsort(newast->array_values, newast->array_size, sizeof(uint64_t), compareI64);
      }
      break;
   case UR_TYPE_IP:
      // Expect the array is pure IP addresses only at first
      newast->ipprefixes = 0;
      newast->array_values_ipprefix = calloc(newast->array_size, sizeof(struct ipprefix));
      for (int i=0; i < newast->array_size; i++) {
         while (isblank(*p) || *p == '\n') {
            /* skip leading spaces */
            p++;
         }

         // Parse mask if it is given
         int prefixlen = 128;
         char *mask = strchr(p, '/');
         if (mask != NULL) {
            // create mask and store it
            prefixlen = atoi(mask + 1);
            *mask = 0;
            mask += 1;
            // switch this array into IP prefixes (different evaluation)
            newast->ipprefixes = 1;
         } else if (newast->ipprefixes == 1) {
            printf("Error: Found IP without prefix after IP with prefix. Please use either IP addresses or IP prefixes.\n");
            newast->id = UR_INVALID_FIELD;
            free(newast->array_values_ipprefix);
            newast->array_values_ipprefix = 0;
            goto parsing_error;
         }

         if (!ip_from_str(p, &newast->array_values_ipprefix[i].ip)) {
            // error
            printf("Error: %s is not a valid IP address. Corresponding rule will always evaluate false.\n", p);
            newast->id = UR_INVALID_FIELD;
            free(newast->array_values_ipprefix);
            newast->array_values_ipprefix = 0;
            goto parsing_error;
         } else {
            if (newast->ipprefixes == 0 && ip_is4(&newast->array_values_ipprefix[i].ip)) {
               prefixlen = 32;
            }
         }

         newast->array_values_ipprefix[i].mask = newast->array_values_ipprefix[i].ip;
         ip_make_mask(&newast->array_values_ipprefix[i].mask, prefixlen);

         if (mask != NULL) {
            ip_mask(&newast->array_values_ipprefix[i].ip, &newast->array_values_ipprefix[i].mask);
            p = mask + strlen(mask) + 1;
         } else {
            if (ip_is4(&newast->array_values_ipprefix[i].mask)) {
               ip_make_mask(&newast->array_values_ipprefix[i].mask, 32);
            } else {
               ip_make_mask(&newast->array_values_ipprefix[i].mask, 128);
            }
            p += strlen(p) + 1;
         }
      }
      qsort(newast->array_values_ipprefix, newast->array_size, sizeof(struct ipprefix), compareIPs);
      break;
   case UR_TYPE_TIME:
      newast->array_values_date = calloc(newast->array_size, sizeof(ur_time_t));
      for (int i=0; i < newast->array_size; i++) {
         if (ur_time_from_string(&newast->array_values_date[i], p) != 0) {
            /* error */
            printf("Error: %s could not be loaded. Expected format: YYYY-mm-ddTHH:MM:SS.sss, (.sss is optional). Eg. 2018-06-27T19:44:41.123.\n", p);
            free(newast->array_values_date);
            newast->array_values_date = 0;
            goto parsing_error;
         }
         p += strlen(p) + 1;
      }
      qsort(newast->array_values_date, newast->array_size, sizeof(ur_time_t), compareUI64);
      break;
   case UR_TYPE_FLOAT:
   case UR_TYPE_DOUBLE:
      newast->array_values_double = calloc(newast->array_size, sizeof(double));
      for (int i=0; i < newast->array_size; i++) {
         if (sscanf(p, "%lf", &newast->array_values_double[i]) != 1) {
            /* error */
            printf("Error: %s could not be parsed.\n", p);
            free(newast->array_values_double);
            newast->array_values_double = 0;
            goto parsing_error;
         }
         p += strlen(p) + 1;
      }

      qsort(newast->array_values_double, newast->array_size, sizeof(double), compareDouble);
      break;
   default:
      /* not supported */
      free(column);
      free(array);
      printf("Type %d is not supported.\n", newast->field_type);
      free(newast);
      return NULL;
   }

   free(array);
   return (struct ast *) newast;

parsing_error:
   free(column);
   free(array);
   free(newast);
   return NULL;
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
   int id, iddst, host = 0;
   newast->type = NODE_T_IP;
   newast->column = column;
   newast->id = UR_INVALID_FIELD;
   newast->dstid = UR_INVALID_FIELD;
   newast->cmp = get_op_type(cmp);
   free(cmp);

   if (!ip_from_str(ipAddr, &(newast->ipAddr))) {
      printf("Warning: %s is not a valid IP address. Corresponding rule will always evaluate false.\n", ipAddr);
      newast->id = UR_INVALID_FIELD;
      free(ipAddr);
      return (struct ast *) newast;
   }
   free(ipAddr);

   if (strcmp(column, "host") == 0) {
      // "host" was given in column name, consider SRC & DST
      id = ur_get_id_by_name("SRC_IP");
      iddst = ur_get_id_by_name("DST_IP");
      host = 1;
   } else {
      id = ur_get_id_by_name(column);
   }

   if (id == UR_E_INVALID_NAME) {
      printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
   } else if (ur_get_type(id) != UR_TYPE_IP) {
      printf("Warning: Type of %s is not IP address. Corresponding rule will always evaluate false.\n", column);
   } else {
      newast->id = id;
   }
   if (host == 1) {
      if (iddst == UR_E_INVALID_NAME) {
         printf("Warning: DST field is not present in input format. Corresponding rule will always evaluate false.\n");
      } else {
         newast->dstid = iddst;
      }
   }
   return (struct ast *) newast;
}

struct ast *newIPNET(char *column, char *cmp, char *ipAddr)
{
   int id, iddst, host = 0;
   struct ipnet *newast = (struct ipnet *) malloc(sizeof(struct ipnet));
   newast->type = NODE_T_NET;
   newast->column = column;
   newast->id = UR_INVALID_FIELD;
   newast->dstid = UR_INVALID_FIELD;

   newast->cmp = get_op_type(cmp);
   free(cmp);

   char *mask = strchr(ipAddr, '/');
   if (mask == NULL) {
      printf("Warning: %s is not a valid IP subnet. Corresponding rule will always evaluate false.\n", ipAddr);
      return (struct ast *) newast;
   }
   newast->mask = atoi(mask + 1);
   *mask = '\0';

   if (!ip_from_str(ipAddr, &(newast->ipAddr))) {
      printf("Warning: %s is not a valid IP address. Corresponding rule will always evaluate false.\n", ipAddr);
      free(ipAddr);
      return (struct ast *) newast;
   }
   free(ipAddr);

   newast->ipMask = newast->ipAddr;
   ip_make_mask(&newast->ipMask, newast->mask);
   ip_mask(&newast->ipAddr, &newast->ipMask);

   if (strcmp(column, "host") == 0) {
      // "host" was given in column name, consider SRC & DST
      id = ur_get_id_by_name("SRC_IP");
      iddst = ur_get_id_by_name("DST_IP");
      host = 1;
   } else {
      id = ur_get_id_by_name(column);
   }

   if (id == UR_E_INVALID_NAME) {
      printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
   } else if (ur_get_type(id) != UR_TYPE_IP) {
      printf("Warning: Type of %s is not IP address. Corresponding rule will always evaluate false.\n", column);
   } else {
      newast->id = id;
   }

   if (host == 1) {
      if (iddst == UR_E_INVALID_NAME) {
         printf("Warning: DST field of host is not present in input format. Only SRC field will be considered.\n");
      } else {
         newast->dstid = iddst;
      }
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
         free(s);
         newast->id = UR_INVALID_FIELD;
         return (struct ast *) newast;
      }
      free(s);
   } else {
      newast->s = s;
   }
   int id = ur_get_id_by_name(column);
   if (id == UR_E_INVALID_NAME) {
      printf("Warning: %s is not present in input format. Corresponding rule will always evaluate false.\n", column);
      newast->id = UR_INVALID_FIELD;
   } else if (ur_get_type(id) != UR_TYPE_STRING && 
            ur_get_type(id) != UR_TYPE_BYTES &&
            ur_get_type(id) != UR_TYPE_CHAR) {
      printf("Warning: Type of %s is not string. Corresponding rule will always evaluate false.\n", column);
      newast->id = UR_INVALID_FIELD;
   } else {
      newast->id = id;
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

struct ast *newNegation(struct ast *b)
{
   struct brack *newast = (struct brack *) malloc(sizeof(struct brack));
   newast->type = NODE_T_NEGATION;
   newast->b = b;
   return (struct ast *) newast;
}

void printAST(struct ast *ast)
{
   char *TTY_RED = "";
   char *TTY_RESET = "";
   if (isatty(fileno(stdout))) {
      TTY_RED = ANSI_COLOR_RED;
      TTY_RESET = ANSI_COLOR_RESET;
   }
   if (ast == NULL) {
      puts(ANSI_COLOR_RED "SYNTAX ERROR" ANSI_COLOR_RESET);
      return;
   }
   
   switch (ast->type) {
   case NODE_T_AST:
      printAST(ast->l);

      if (ast->operator == OP_OR) {
         printf(" || ");
      } else if (ast->operator == OP_AND) {
         printf(" && ");
      }
      if (ast->r) {
         printAST(ast->r);
      }
      break;

   case NODE_T_BOOLEAN: {
      struct boolean *b = (struct boolean *) ast;
      if (b->value) {
         printf("TRUE");
      } else {
         printf("FALSE");
      }

      break;
   }

   case NODE_T_EXPRESSION:
      if (((struct expression*) ast)->id == UR_INVALID_FIELD) { // There was error with this expr., print it in red color
         printf("%s", TTY_RED);
      }
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
      if (((struct expression*) ast)->is_signed) {
         printf("%" PRId64, ((struct expression*) ast)->number);
      } else {
         printf("%" PRIu64, (uint64_t) ((struct expression*) ast)->number);
      }
      if (((struct expression*) ast)->id == UR_INVALID_FIELD) {
         printf("%s", TTY_RESET);
      }
      break;
   case NODE_T_EXPRESSION_PORT:
      printf("port");

      switch (((struct expression_port*) ast)->cmp) {
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
      printf("%" PRIu64, (uint64_t) ((struct expression_port*) ast)->number);
      break;

   case NODE_T_EXPRESSION_FP:
   case NODE_T_EXPRESSION_DATETIME:
      if (((struct expression_fp*) ast)->id == UR_INVALID_FIELD) { // There was error with this expr., print it in red color
         printf("%s", TTY_RED);
      }
      printf("%s", ((struct expression_fp*) ast)->column);

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
      if (ast->type == NODE_T_EXPRESSION_FP) {
         printf("%lf", ((struct expression_fp*) ast)->number);
      } else if (ast->type == NODE_T_EXPRESSION_DATETIME) {
         ur_time_t t = ((struct expression_datetime *) ast)->date;
         time_t sec = ur_time_get_sec(t);
         int msec = ur_time_get_msec(t);
         char str[32];
         struct tm tmp_tm;
         strftime(str, 31, "%FT%T", gmtime_r(&sec, &tmp_tm));
         printf("%s.%03i", str, msec);
      }
      if (((struct expression_fp*) ast)->id == UR_INVALID_FIELD) {
         printf("%s", TTY_RESET);
      }
      break;

   case NODE_T_EXPRESSION_ARRAY: {
      struct expression_array *array = (struct expression_array *) ast;
      if (array->id == UR_INVALID_FIELD) { // There was error with this expr., print it in red color
         printf("%s", TTY_RED);
      }
      printf("%s", array->column);
      if (array->id == UR_INVALID_FIELD) {
         printf("%s", TTY_RESET);
      }

      printf(" IN [");
      if (array->id != UR_INVALID_FIELD) {
         for (int i=0; i < array->array_size; i++) {
            switch (array->field_type) {
            case UR_TYPE_UINT8:
            case UR_TYPE_UINT16:
            case UR_TYPE_UINT32:
            case UR_TYPE_UINT64:
               printf("%"PRIu64", ", array->array_values[i]);
               break;
            case UR_TYPE_INT8:
            case UR_TYPE_INT16:
            case UR_TYPE_INT32:
            case UR_TYPE_INT64:
               printf("%"PRIi64", ", array->array_values[i]);
               break;
            case UR_TYPE_IP:
            {
               char ipstr[INET6_ADDRSTRLEN];
               ip_to_str(&array->array_values_ipprefix[i].ip, ipstr);
               printf("%s/", ipstr);
               ip_to_str(&array->array_values_ipprefix[i].mask, ipstr);
               printf("%s, ", ipstr);
               break;
            }
            case UR_TYPE_TIME:
            {
               time_t sec = ur_time_get_sec(array->array_values_date[i]);
               int msec = ur_time_get_msec(array->array_values_date[i]);
               char str[32];
               struct tm tmp_tm;
               strftime(str, 31, "%FT%T", gmtime_r(&sec, &tmp_tm));
               printf("%s.%03i, ", str, msec);
               break;
            }
            case UR_TYPE_FLOAT:
            case UR_TYPE_DOUBLE:
               printf("%lf"", ", array->array_values_double[i]);
               break;
            default:
               /* not supported yet */
               printf("Type %d is not supported.\n", array->field_type);
            }
         }
      }
      printf("]");

      break;
   }

   case NODE_T_PROTOCOL:
      printf("PROTOCOL %s %s",
            ((struct protocol*) ast)->cmp,
            ((struct protocol*) ast)->data);
      break;

   case NODE_T_NET: {
      char str[46];
      struct ipnet *ipnet = (struct ipnet *) ast;
      if (ipnet->id == UR_INVALID_FIELD) { // There was error with this expr., print it in red color
         printf("%s", TTY_RED);
      }
      printf("%s", ipnet->column);

      switch (ipnet->cmp) {
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
      ip_to_str(&ipnet->ipAddr, str);
      printf("%s/%" PRIu8, str, ipnet->mask);
      ip_to_str(&ipnet->ipMask, str);
      printf(" (%s)" , str);

      if (ipnet->id == UR_INVALID_FIELD) {
         printf("%s", TTY_RESET);
      }

      break;
   }

   case NODE_T_IP: {
      char str[46];
      struct ip *ip = (struct ip *) ast;
      if (ip->id == UR_INVALID_FIELD) { // There was error with this expr., print it in red color
         printf("%s", TTY_RED);
      }
      printf("%s", ip->column);

      switch (ip->cmp) {
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

      ip_to_str(&ip->ipAddr, str);
      printf("%s", str);
      if (ip->id == UR_INVALID_FIELD) {
         printf("%s", TTY_RESET);
      }

      break;
   }

   case NODE_T_STRING:
      if (((struct str*) ast)->id == UR_INVALID_FIELD) { // There was error with this expr., print it in red color
         printf("%s", TTY_RED);
      }
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
      if (((struct str*) ast)->id == UR_INVALID_FIELD) {
         printf("%s", TTY_RESET);
      }
      break;

   case NODE_T_BRACKET:
      printf("( ");
      printAST(((struct brack*) ast)->b);
      printf(" )");
      break;

   case NODE_T_NEGATION:
      printf("! ( ");
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
      freeAST(ast->r);
      break;
   case NODE_T_EXPRESSION:
      free(((struct expression *) ast)->column);
      ((struct expression *) ast)->column = NULL;
      break;
   case NODE_T_BOOLEAN:
   case NODE_T_EXPRESSION_PORT:
      /* nothing was allocated */
      break;
   case NODE_T_EXPRESSION_FP:
      free(((struct expression_fp *) ast)->column);
      break;
   case NODE_T_EXPRESSION_DATETIME:
      free(((struct expression_datetime *) ast)->column);
      break;
   case NODE_T_EXPRESSION_ARRAY:
      free(((struct expression_array *) ast)->column);
      free(((struct expression_array *) ast)->array_values);
      free(((struct expression_array *) ast)->array_values_ipprefix);
      free(((struct expression_array *) ast)->array_values_date);
      free(((struct expression_array *) ast)->array_values_double);
      break;
   case NODE_T_PROTOCOL:
      free(((struct protocol*) ast)->cmp);
      free(((struct protocol*) ast)->data);
      break;
   case NODE_T_NET:
      free(((struct ipnet *) ast)->column);
      break;
   case NODE_T_IP:
      free(((struct ip *) ast)->column);
      break;
   case NODE_T_STRING:
      free(((struct str*) ast)->column);
      free(((struct str*) ast)->s);
      if (((struct str*) ast)->cmp == OP_RE) {
         regfree(&((struct str*) ast)->re);
      }
      ((struct str*) ast)->s = NULL;
      break;
   case NODE_T_BRACKET:
   case NODE_T_NEGATION:
      freeAST(((struct brack*) ast)->b);
      break;
   }
   free(ast);
}


int compareUnsigned(uint64_t a, uint64_t b, cmp_op op) {
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
      default:
         fprintf(stderr, "Warning: Invalid comparison operator.\n");
         return 0;
   }
   return 0;
}

int compareSigned(int64_t a, int64_t b, cmp_op op) {
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
      default:
         fprintf(stderr, "Warning: Invalid comparison operator.\n");
         return 0;
   }
   return 0;
}

int compareFloating(double a, double b, cmp_op op) {
   double EPS = 1e-8;
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
         return abs(a - b) < EPS;
      default:
         fprintf(stderr, "Warning: Invalid comparison operator.\n");
         return 0;
   }
   return 0;
}

int compareElemInArray(void *val, struct expression_array *ast)
{
   void *res = NULL;

   uint64_t val_u;
   int64_t val_i;
   double val_f;

   switch (ast->field_type) {
   case UR_TYPE_UINT8:
      val_u = *((uint8_t *) val);
      res = bsearch(&val_u, ast->array_values, ast->array_size, sizeof(uint64_t), compareUI64);
      break;
   case UR_TYPE_UINT16:
      val_u = *((uint16_t *) val);
      res = bsearch(&val_u, ast->array_values, ast->array_size, sizeof(uint64_t), compareUI64);
      break;
   case UR_TYPE_UINT32:
      val_u = *((uint32_t *) val);
      res = bsearch(&val_u, ast->array_values, ast->array_size, sizeof(uint64_t), compareUI64);
      break;
   case UR_TYPE_UINT64:
      val_u = *((uint64_t *) val);
      res = bsearch(&val_u, ast->array_values, ast->array_size, sizeof(uint64_t), compareUI64);
      break;
   case UR_TYPE_INT8:
      val_i = *((uint8_t *) val);
      res = bsearch(&val_i, ast->array_values, ast->array_size, sizeof(int64_t), compareI64);
      break;
   case UR_TYPE_INT16:
      val_i = *((uint16_t *) val);
      res = bsearch(&val_i, ast->array_values, ast->array_size, sizeof(int64_t), compareI64);
      break;
   case UR_TYPE_INT32:
      val_i = *((uint32_t *) val);
      res = bsearch(&val_i, ast->array_values, ast->array_size, sizeof(int64_t), compareI64);
      break;
   case UR_TYPE_INT64:
      val_i = *((uint64_t *) val);
      res = bsearch(&val_i, ast->array_values, ast->array_size, sizeof(int64_t), compareI64);
      break;
   case UR_TYPE_IP:
      if (ast->ipprefixes == 0) {
         res = bsearch(val, ast->array_values_ipprefix, ast->array_size, sizeof(struct ipprefix), compareIPs);
      } else {
         res = bsearch(val, ast->array_values_ipprefix, ast->array_size, sizeof(struct ipprefix), compareIPwithPrefix);
      }
      break;
   case UR_TYPE_TIME:
      res = bsearch(val, ast->array_values_date, ast->array_size, sizeof(ur_time_t), compareUI64);
      break;
   case UR_TYPE_FLOAT:
      val_f = (double) *((float *) val);
      res = bsearch(&val_f, ast->array_values_double, ast->array_size, sizeof(double), compareDouble);
      break;
   case UR_TYPE_DOUBLE:
      res = bsearch(val, ast->array_values_double, ast->array_size, sizeof(double), compareDouble);
      break;
   default:
      /* not supported yet */
      printf("Type %d is not supported.\n", ast->field_type);
      return 0;
   }

   return (res != NULL);
}

int evalAST(struct ast *ast, const ur_template_t *in_tmplt, const void *in_rec)
{
   size_t size;
   char *expr;
   int is_equal;

   if (!ast) {
      return 0; // NULL
   }
   switch (ast->type) {
   case NODE_T_AST:
      if (ast->operator == OP_NOP) {
         return evalAST(ast->l, in_tmplt, in_rec);
      } else if (ast->operator == OP_OR) {
         return (evalAST(ast->l, in_tmplt, in_rec) || evalAST(ast->r, in_tmplt, in_rec) ? 1 : 0);
      } else if (ast->operator == OP_AND) {
         return (evalAST(ast->l, in_tmplt, in_rec) && evalAST(ast->r, in_tmplt, in_rec) ? 1 : 0);
      } else {
         fprintf(stderr, "Warning: Unknown operator in NODE_T_AST.\n");
         return 0;
      }
   case NODE_T_BOOLEAN:
      return ((struct boolean*) ast)->value;
   case NODE_T_EXPRESSION:
      if (((struct expression*) ast)->id == UR_INVALID_FIELD) {
         return 0;
      }
      int type = ur_get_type(((struct expression*) ast)->id);
      switch (type) {
      case UR_TYPE_UINT8:
         return compareSigned(*(uint8_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT8:
         return compareUnsigned(*(int8_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT16:
         return compareSigned(*(int16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_UINT16:
         return compareUnsigned(*(uint16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT32:
         return compareSigned(*(int32_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_UINT32:
         return compareUnsigned(*(uint32_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_INT64:
         return compareSigned(*(int64_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      case UR_TYPE_UINT64:
         return compareUnsigned(*(uint64_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression*) ast)->id)), ((struct expression*) ast)->number, ((struct expression*) ast)->cmp);
      }
      return 0;
   case NODE_T_EXPRESSION_FP:
      if (((struct expression_fp*) ast)->id == UR_INVALID_FIELD) {
         return 0;
      }
      return compareFloating(*(double *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression_fp*) ast)->id)), ((struct expression_fp*) ast)->number, ((struct expression_fp*) ast)->cmp);
   case NODE_T_EXPRESSION_DATETIME:
      if (((struct expression*) ast)->id == UR_INVALID_FIELD) {
         return 0;
      }

      return compareUnsigned(*(ur_time_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression_datetime *) ast)->id)),
                             ((struct expression_datetime *) ast)->date, ((struct expression_datetime *) ast)->cmp);

   case NODE_T_EXPRESSION_PORT: {
      struct expression_port *port = (struct expression_port *) ast;
      cmp_op cmp = port->cmp;
      if (port->srcport == UR_INVALID_FIELD || port->dstport == UR_INVALID_FIELD) {
         return 0;
      }
      int cmp_res1 = compareUnsigned(*(uint16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, port->srcport)), port->number, cmp);
      int cmp_res2 = compareUnsigned(*(uint16_t *)(ur_get_ptr_by_id(in_tmplt, in_rec, port->dstport)), port->number, cmp);
      return cmp_res1 || cmp_res2;
   }

   case NODE_T_EXPRESSION_ARRAY: {
         if (((struct expression_array*) ast)->id == UR_INVALID_FIELD) {
            return 0;
         }

         int result = 0;
         /* This test should be probably everywhere */
         if (ur_is_present(in_tmplt, ((struct expression_array*) ast)->id)) {
            void *field_val = ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression_array*) ast)->id);
            result = compareElemInArray(field_val, (struct expression_array *) ast);
            if (result != 0) {
               return 1;
            }
         } else {
            printf("Error: Field '%s' is not in the UniRec template.\n", ((struct expression_array*) ast)->column);
            return 0;
         }

         if (((struct expression_array*) ast)->dstid != UR_INVALID_FIELD && ur_is_present(in_tmplt, ((struct expression_array*) ast)->dstid)) {
            void *field_val = ur_get_ptr_by_id(in_tmplt, in_rec, ((struct expression_array*) ast)->dstid);
            return compareElemInArray(field_val, (struct expression_array *) ast);
         } else {
            return 0;
         }
   }

   case NODE_T_NET: {
      struct ipnet *ipnet = (struct ipnet*) ast;
      int cmp_res1, cmp_res2, settype;
      cmp_op cmp = ipnet->cmp;
      settype = ip_is4(&(ipnet->ipAddr));

      if (ipnet->id == UR_INVALID_FIELD) {
         return 0;
      }
      ip_addr_t cur_ip = *((ip_addr_t *) (ur_get_ptr_by_id(in_tmplt, in_rec, ipnet->id)));

      /* check if both IPs are of the same version and return if not */
      if (ip_is4(&cur_ip) != settype) {
         return cmp == OP_NE || cmp == OP_LT || cmp == OP_GT;
      }

      /* mask current IP and then just compare it */
      ip_mask(&cur_ip, &(ipnet->ipMask));
      cmp_res1 = ip_cmp(&cur_ip, &(ipnet->ipAddr));

      if (ipnet->dstid == UR_INVALID_FIELD) {
         // we do not have DST, this is final result
         if (cmp_res1 == 0) {
            // Same addresses
            return cmp == OP_EQ || cmp == OP_LE || cmp == OP_GE;
         } else if (cmp_res1 < 0) {
            // Address in record is lower than the given one
            return cmp == OP_NE || cmp == OP_LT || cmp == OP_LE;
         } else {
            // Address in record is higher than the given one
            return cmp == OP_NE || cmp == OP_GT || cmp == OP_GE;
         }
      }

      // we have DST, process it
      cur_ip = *((ip_addr_t *) (ur_get_ptr_by_id(in_tmplt, in_rec, ipnet->dstid)));

      /* mask current IP and then just compare it */
      ip_mask(&cur_ip, &(ipnet->ipMask));
      cmp_res2 = ip_cmp(&cur_ip, &(ipnet->ipAddr));

      // combine results from SRC and DST
      if (cmp_res1 == 0 || cmp_res2 == 0) {
         // Same addresses
         return cmp == OP_EQ || cmp == OP_LE || cmp == OP_GE;
      } else if (cmp_res1 < 0 || cmp_res2 < 0) {
         // Address in record is lower than the given one
         return cmp == OP_NE || cmp == OP_LT || cmp == OP_LE;
      } else {
         // Address in record is higher than the given one
         return cmp == OP_NE || cmp == OP_GT || cmp == OP_GE;
      }
   }
   case NODE_T_IP: {
      struct ip *ip = (struct ip*) ast;
      int cmp_res1, cmp_res2;
      cmp_op cmp = ip->cmp;
      if (ip->id == UR_INVALID_FIELD) {
         return 0;
      }
      cmp_res1 = ip_cmp((ip_addr_t *) (ur_get_ptr_by_id(in_tmplt, in_rec, ip->id)), &ip->ipAddr);

      if (ip->dstid == UR_INVALID_FIELD) {
         // we do not have DST, this is final result
         if (cmp_res1 == 0) {
            // Same addresses
            return cmp == OP_EQ || cmp == OP_LE || cmp == OP_GE;
         } else if (cmp_res1 < 0) {
            // Address in record is lower than the given one
            return cmp == OP_NE || cmp == OP_LT || cmp == OP_LE;
         } else {
            // Address in record is higher than the given one
            return cmp == OP_NE || cmp == OP_GT || cmp == OP_GE;
         }
      }

      // we have DST, process it
      cmp_res2 = ip_cmp((ip_addr_t *) (ur_get_ptr_by_id(in_tmplt, in_rec, ip->dstid)), &(ip->ipAddr));
      // combine results from SRC and DST
      if (cmp_res1 == 0 || cmp_res2 == 0) {
         // At least one address is same
         return cmp == OP_EQ || cmp == OP_LE || cmp == OP_GE;
      } else if (cmp_res1 < 0 || cmp_res2 < 0) {
         // At least one address in record is lower than the given one
         return cmp == OP_NE || cmp == OP_LT || cmp == OP_LE;
      } else {
         // At least one address in record is higher than the given one
         return cmp == OP_NE || cmp == OP_GT || cmp == OP_GE;
      }
   }
   case NODE_T_STRING:
      size = ur_get_var_len(in_tmplt, in_rec, ((struct str*) ast)->id); // only relevant for strings
      expr = (char *)(ur_get_ptr_by_id(in_tmplt, in_rec, ((struct str*) ast)->id));

      if (((struct str*) ast)->id == UR_INVALID_FIELD) {
         return 0;
      }
      // char
      if (ur_get_type(((struct str*) ast)->id) == UR_TYPE_CHAR) {
         // boolean value - record matches filter
         is_equal = (strlen(((struct str*) ast)->s) == 1 && *(((struct str*) ast)->s) == *expr);
         // return value depending on used operator (1 and OP_EQ || 0 and OP_NE)
         return is_equal == (((struct str*) ast)->cmp == OP_EQ);
      } else { // string
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
            // boolean value - record matches filter
            // strings are the same in size & content (size comparisson necessary for zero-sized strings)
            is_equal = (strlen(((struct str*) ast)->s) == size && strncmp(((struct str*) ast)->s, expr, size) == 0);
            // return value depending on used operator (1 and OP_EQ || 0 and OP_NE)
            return is_equal == (((struct str*) ast)->cmp == OP_EQ);
         }
      }
   case NODE_T_BRACKET:
      return evalAST(((struct brack*) ast)->b, in_tmplt, in_rec);
   case NODE_T_NEGATION:
      return ! evalAST(((struct brack*) ast)->b, in_tmplt, in_rec);
   default:
      fprintf(stderr, "Warning: Unknown node type.\n");
      return 0;
   }
}

void changeProtocol(struct ast **ast)
{
   int protocol = 0;
   struct protoent *proto = NULL;
   char *cmp, *column;

   if (!(*ast)) {
      return; // NULL
   }

   switch ((*ast)->type) {
   case NODE_T_AST:
      changeProtocol(&((*ast)->l));
      changeProtocol(&((*ast)->r));
      return;
   case NODE_T_EXPRESSION:
   case NODE_T_BOOLEAN:
   case NODE_T_EXPRESSION_PORT:
   case NODE_T_EXPRESSION_FP:
   case NODE_T_EXPRESSION_DATETIME:
   case NODE_T_EXPRESSION_ARRAY:
      return;
   case NODE_T_PROTOCOL:
      proto = getprotobyname(((struct protocol *) (*ast))->data);
      if (proto != NULL) {
         protocol = proto->p_proto;
      } else {
         fprintf(stderr, "Error: Protocol %s is not known, revisit /etc/protocols.\n", (((struct protocol *) (*ast))->data));
      }
      cmp = ((struct protocol*) (*ast))->cmp;
      free(((struct protocol*) (*ast))->data);
      free(*ast);
      column = strdup("PROTOCOL");
      *ast = newExpression(column, cmp, protocol, 0);
      return;
   case NODE_T_IP:
   case NODE_T_NET:
   case NODE_T_STRING:
   case NODE_T_NEGATION:
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

struct ast *getTree(const char *str, const char *port_number)
{
   struct ast *result;
   if (str == NULL || str[0] == '\0') {
      printf("[%s] No Filter.\n", port_number);
      return NULL;
   }
   #ifdef YYDEBUG
   yydebug = 1;
   #endif
   yy_scan_string(str);

   if (yyparse()) {        // failure
      result = NULL;
   } else {
      result = main_tree;  // success
   }
   yy_delete_buffer(get_buf());

   printf("[%s] Filter: ", port_number);
   printAST(result);
   printf("\n");

   return result;
}
