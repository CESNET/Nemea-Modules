/**
 * \file unirecfilter.h
 * \brief NEMEA module selecting records and sending specified fields.
 * \author Zdenek Kasner <kasnezde@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Miroslav Kalina <kalinmi2@fit.cvut.cz>
 * \date 2016
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
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *   may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
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
#ifndef UNIRECFILTER_H
#define UNIRECFILTER_H

#include <unirec/unirec.h>
#include <sys/types.h>
#include <regex.h>
#include <liburfilter.h>

#define DYN_FIELD_MAX_SIZE 1024 // Maximal size of dynamic field, longer fields will be cutted to this size

#define SET_NULL(field_id, tmpl, data) \
memset(ur_get_ptr_by_id(tmpl, data, field_id), 0, ur_get_size(field_id));

extern char * str_buffer;

/* Structure with information for each output interface */
struct unirec_output_t {
   char *output_specifier_str; /**< unirecfilter parameters syntax output specifier string */
   char *unirec_output_specifier; /**< unirec output specifier string */
   char *filter_str; /**< loaded filter string */
   urfilter_t *filter; /**< filter structure */
   ur_template_t *out_tmplt; /**< unirec output template */
   void *out_rec; /**< message to be sent */
};

/** \brief search for character delimiter in string
 * Searches given string for the first occurance of given one char delimiter and returns it's position.
 * \param[in] ptr input string
 * \param[in] delim delimiter of which first occurence we try to find.
 * \return  pointer to position of first appearance of the delimiter in the string, NULL if there is none
 */
char *skip_str_chr(char *ptr, char delim);

/** \brief set default value to output specifier
 * Sets default value in output specifier if given in input parameter, otherwise sets it to NULL value.
 * \param[in] output_specifier value to be set as default
 * \return 0 for success, 1 if error occured
 */
int set_default_values(struct unirec_output_t *output_specifier);

/** \brief clears values from output specifier fields
 * Takes the given output_specifier and clears values assigned to all fields while preserving the name of value.
 * \param[in] output_specifier unirec output specifier
 * \return  0 on success, 1 if error occured
 */
int parse_output_specifier_from_str(struct unirec_output_t *output_specifier);

/** \brief loads output specifiers from file and fills them into unirec_output_t
 * searches given string for the first occurance of given one char delimiter and returns it's position.
 * \param[in] str input string - whole file loaded to char *
 * \param[in] output_specifiers unirec output specifiers structure
 * \param[in] n_outputs number of output interfaces
 * \return  number of successfully loaded interfaces
 */
int parse_file(char *str, struct unirec_output_t **output_specifiers, int n_outputs);

/** \brief loads file to a buffer
 * Open and load the whole file to a buffer returning pointer to it.
 * \param[in] filename path of file with configuration
 * \return pointer to the buffer, NULL if loading failed
 */
char *load_file(char *filename);

/** \brief loads filters from file and fills them into unirec_output_t
 * loads filters from file on given path, checks if it matches expected number and fills unirec_output_t
 * \param[in] filename path of file with configuration
 * \param[in] output_specifiers unirec output specifiers structure
 * \param[in] n_outputs number of filters that are expected in file
 * \return  number of successfully loaded filters
 */
int get_filter_from_file(char *filename, struct unirec_output_t **output_specifiers, int n_outputs);

/** \brief Create templates based on data from filter
 * Creates templates for all output interfaces based on data from filter.
 * \param[in] n_outputs number of output interfaces
 * \param[in] port_numbers array with port numbers
 * \param[in] output_specifiers array of output specifiers
 * \return 0 on success, non-zero on fail
 */
int create_templates(int n_outputs, char **port_numbers, struct unirec_output_t **output_specifiers);
#endif

