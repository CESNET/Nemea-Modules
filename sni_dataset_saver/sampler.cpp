/**
 * \file sampler.cpp
 * \brief Implementation of flow sampler. 
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

#include <ctime>
#include <iostream>
#include <algorithm>

#include "sampler.h"

constexpr uint16_t default_sampling_rate = 10;
constexpr time_t default_timeout = 300; /* seconds */

time_t Sampler::_timeout = default_timeout;

Sampler::Sampler()
{
    _recent_timestamp = 0;
    _counter = 0;
    _sampled_counter = 0;
    is_enabled = true;
    _rate = 10;
}

void Sampler::set_timeout(time_t timeout) noexcept
{
    _timeout = timeout;
}

void Sampler::set_total_counter(uint64_t counter) noexcept
{
    _counter = counter;
}

uint64_t Sampler::get_total_counter() noexcept
{
    return _counter;
}

uint64_t Sampler::get_sampled_counter() noexcept
{
    return _sampled_counter;
}

bool Sampler::is_timeouted(time_t first) noexcept
{
    return first > _recent_timestamp + _timeout;
}

void Sampler::update_recent_timestamp(time_t last)
{
    _recent_timestamp = std::max(_recent_timestamp, last);
}

void Sampler::enable_sampling(uint16_t rate = 10) noexcept
{
    is_enabled = true;
    _rate = rate;
}

void Sampler::disable_sampling() noexcept
{
    is_enabled = false;
}

bool Sampler::should_be_sampled(time_t first, time_t last)
{
    _counter++;
    if (is_enabled == false) {
        return false;
    }

    if (is_timeouted(first) == true) {
        update_recent_timestamp(last);
        return false;

    }
        
    update_recent_timestamp(last);
    if (_counter % _rate == 0) {
        return false;
    }

    _sampled_counter++;
    return true;
}