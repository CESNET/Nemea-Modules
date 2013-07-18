/*!
 * \file traffic_repeater.h
 * \brief Example module for simple traffic forwarding from server to client.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
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

#ifndef _TRAFFIC_REPEATER_H_
#define _TRAFFIC_REPEATER_H_

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <commlbr.h>
#include <libtrap/trap.h>

/*!
 * \name Default values
 *  Defines macros used by traffic repeater. 
 * \{ */
#define IFC_DEF 1 /*< Default number of intefaces, do not change. */
#define BUFFER_TMP 128 /*< Size of a temporary buffer. */
/*! \} */

static char stop = 0; /*!< Global variable used by signal handler to end the traffic repeater. */

/*!
 * \brief Signal function.
 * Function to catch signal termination or interrupt and set the global variable.
 * \param[in] signal Number of signal which have been caught.
 */
void signal_handler(int signal);

/*!
 * \brief Module initialization.
 * Function to initialize the module structure by given values.
 * \param[out] module Pointer to a module structure to be initialized.
 * \param[in] ifc_in Number of client interfaces.
 * \param[in] ifc_out Number of server interfaces.
 */
void module_init(trap_module_info_t *module, int ifc_in, int ifc_out);

/*!
 * \brief Traffic repeater initialization.
 * Function to initialize the traffic repeater. 
 * \param[in] module_info Pointer to module structure used by TRAP.
 * \param[in] ifc_spec Pointer to interface structure used by TRAP.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int repeater_init(trap_module_info_t *module_info, trap_ifc_spec_t *ifc_spec);

/*!
 * \brief Traffic repeater function
 * Function to resend received data from input interface to output interface. 
 */
void traffic_repeater(void);

/*!
 * \brief Main function.
 * Main function to parse given arguments and run the traffic repeater.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int main(int argc, char **argv);

#endif /* _TRAFFIC_REPEATER_H_ */
