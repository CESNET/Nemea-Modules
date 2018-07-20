/**
 * \file bloom.c
 * \brief History of communicating entities using bloom filters.
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2013,2014,2015,2016,2017,2018 CESNET
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <stdint.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"


UR_FIELDS (
    ipaddr SRC_IP,
    ipaddr DST_IP
)

trap_module_info_t *module_info = NULL;

//BASIC(char *, char *, int, int)
#define MODULE_BASIC_INFO(BASIC) \
    BASIC("History gathering module", \
          "This module gathers history of communicating entities and stores them in a bloom filter.", 1, 0)

/* TODO params
    - bloom filter parameters
         - expected size
         - false positive rate
    - protected prefix (so we can decide which addr we want to insert)
    - interval after which we want to create new filter and send the old one (short periond~5min in the original design)
    - ip addr of hitory service
*/
/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
    PARAM('c', "count", "Expected number of distinct addresess for aggregated period.", required_argument, "int32") \
    PARAM('e', "error", "False possitive error rate at \"count\" entries.", required_argument, "float")
    //PARAM(char, char *, char *, no_argument  or  required_argument, char *)
/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */


static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


int main(int argc, char **argv)
{
    int ret;
    signed char opt;
    int32_t count;
    double fp_error_rate;
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];

    /* TRAP initialization */
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
    TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
 
    while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                break;
            case 'e':
                fp_error_rate = atof(optarg);
                break;
            default:
                fprintf(stderr, "Invalid arguments.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
        }
    }

    /* Create UniRec templates */
    ur_template_t *in_tmplt = ur_create_input_template(0, "SRC_IP,DST_IP", NULL);
    if (in_tmplt == NULL){
        fprintf(stderr, "Error: Input template could not be created.\n");
        return -1;
    }

    /* Main processing loop */
    while (!stop) {
        const void *in_rec;
        uint16_t in_rec_size;
        ip_addr_t src_ip, dst_ip;

        ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

        TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

        if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
            if (in_rec_size <= 1) {
                break; // End of data (used for testing purposes)
            } else {
                fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                        ur_rec_fixlen_size(in_tmplt), in_rec_size);
                break;
            }
        }
        
        /* TODO Process the data */
        src_ip = ur_get(in_tmplt, in_rec, F_SRC_IP);
        dst_ip = ur_get(in_tmplt, in_rec, F_DST_IP);
        ip_to_str(&src_ip, src_ip_str);
        ip_to_str(&dst_ip, dst_ip_str);
        printf("%s, %s, %d, %f\n", src_ip_str, dst_ip_str, count, fp_error_rate);
    }

    /* Cleanup */
    TRAP_DEFAULT_FINALIZATION();
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    ur_free_template(in_tmplt);
    ur_finalize();

    return 0;
}

