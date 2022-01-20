/**
 * \file sampler.h
 * \brief Interface of flow sampler. 
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

#ifndef SAMPLER_H_
#define SAMPLER_H_

#include <ctime>
#include <iostream>

/**
 * @brief  Flow sampler.
 */
class Sampler 
{
    uint16_t _rate; /* reverse sampling rate. Every 1:_rate flows should not be sampled. */
    static time_t _timeout; /* of disable sampling */ 

    time_t _recent_timestamp; /* the newest timestamp */
    uint64_t _counter; /* of seen flows. */
    uint64_t _sampled_counter; /* of flows */

    bool is_enabled; /* sampling */

    bool is_timeouted(time_t first) noexcept;
    void update_recent_timestamp(time_t last);

public:

    Sampler();

    static void set_timeout(time_t timeout) noexcept;
    void enable_sampling(uint16_t rate) noexcept;
    void disable_sampling() noexcept;
    void set_total_counter(uint64_t counter) noexcept;

    uint64_t get_total_counter() noexcept;
    uint64_t get_sampled_counter() noexcept;

    bool should_be_sampled(time_t first, time_t last);
};

#endif /* SAMPLER_H_ */