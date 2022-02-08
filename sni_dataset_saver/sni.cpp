/**
 * \file sni.cpp
 * \brief Implementation of SNI context.
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#include <algorithm>

#include "sni.h"

void 
Sni_ctx::remove_whitespaces(std::string& s)
{
    s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
}

void 
Sni_ctx::split_string_to_vector(const std::string& s, const char delimiter, std::vector<std::string>& v)
{
	std::string temp = "";
	for (size_t i = 0; i < s.length(); ++i) {
		if (s[i] == delimiter) {
            remove_whitespaces(temp);
			v.push_back(temp);
			temp = "";
		} else {
			temp.push_back(s[i]);
		}
	}
	v.push_back(temp);
}

bool 
Sni_ctx::has_placeholder_star(const std::string& s)
{
    return s.find("*.") ? false : true;
}

std::string
Sni_ctx::reverse_domain(const std::string& s, bool has_placeholder_star)
{
    if (has_placeholder_star)
       return std::string(s.rbegin(),s.rend() - 2);
    
    return std::string(s.rbegin(),s.rend());
}

std::vector<std::pair<std::string, bool>> 
Sni_ctx::process_merged_domains(const std::string& merged_domains)
{
    std::vector<std::pair<std::string, bool>> domains;
    std::vector<std::string> domains_vector;
    bool has_ph_star;

    split_string_to_vector(merged_domains, ',', domains_vector);
    
    for (auto& domain : domains_vector) {
        has_ph_star = has_placeholder_star(domain);
        domains.emplace_back(std::make_pair(reverse_domain(domain, has_ph_star), has_ph_star));
    }
    return domains;
}

Sni_ctx::Sni_ctx(const std::string& tag, const std::string& merged_domains)
    : tag(tag), reverse_domains(process_merged_domains(merged_domains))
{
}