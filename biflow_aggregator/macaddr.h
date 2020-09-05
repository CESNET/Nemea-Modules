/**
 * @file macaddr.h
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Implementation of Mac addr functions
 * @version 1.0
 * @date 27.10.2020
 *   
 * @copyright Copyright (c) 2020 CESNET
 */

#ifndef MACADDR_H
#define MACADDR_H

#include <cstring>

#include <netinet/ether.h>

class Mac_addr {
    uint8_t bytes[ETH_ALEN];

public:

    Mac_addr()
    {
    }

    Mac_addr(bool max)
    {
        std::memset(bytes, 0xff, ETH_ALEN);
    }

    static int compare(const Mac_addr* lhs, const Mac_addr* rhs)
    {
        return std::memcmp(lhs->bytes, rhs->bytes, ETH_ALEN);
    }

    static void to_string(const Mac_addr *addr, char *str)
    {
        char *tmp = ether_ntoa((const struct ether_addr *) &addr->bytes);
        strcpy(str, tmp);
    }

    Mac_addr* operator=(const Mac_addr* other) noexcept
    {
        std::memcpy(this->bytes, other->bytes, ETH_ALEN);
        return this;
    }

    operator bool() const {
        return true;
    }

};


bool operator<(const Mac_addr& other, const Mac_addr& other1)
{
    if (Mac_addr::compare(&other, &other1) < 0)
        return true;
    return false;
}

bool operator>(const Mac_addr& other, const Mac_addr& other1)
{
    if (Mac_addr::compare(&other, &other1) > 0)
        return true;
    return false;
}

#endif // MACADDR_H