/*!
 * \file traffic_repeater.h
 * \brief Example module for simple traffic forwarding from server to client.
 * \author Jan Neuzil <neuzija1@fit.cvut.cz>
 * \date 2013
 * \date 2014
 */
/*
 * Copyright (C) 2013,2014 CESNET
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

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>

/*!
 * \name Default values
 *  Defines macros used by traffic repeater.
 * \{ */
#define IFC_IN_NUM 1 /*< Number of input interfaces expected by module. */
#define IFC_OUT_NUM 1 /*< Number of output interfaces expected by module. */

#define NS 1000000000 /*< Number of nanoseconds in a second. */
/*! \} */

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
