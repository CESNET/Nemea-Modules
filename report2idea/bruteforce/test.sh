#!/bin/bash

# input data:
in='
H4sIAPD8jFcAA2NiAIPCzILElJQiheAg53jPAJ2SzNxUBRfXEFfnEE9/v/gQT19XndLMvBJjIwXX
MFe/kPhgZ0cfiJChmYJLcEh8gH9QCJhvoRAQ5B/i7+zvA+WGOwa5uALNiAxw1SkuKcrMS1fw8w9x
ZWBgNGYIYIACRiZmtv9A8PnvlR1RfvlhckAxMQY2JgYGHQZPK0MTcz0jU0M9Yz1DQyMdZJ4xEs9Y
x98Kv4ni5JjoAjORjZGJHWTiXRW2xKDlhWFVQLFmDpCJCkgmWuoZWhoA9aHy8ZvCI06kKYwMAFPH
08ewAQAA
'

# output data:
out='
H4sIAC6kWVwAA92RS2vbQBSF9/0VYtYdMU+9dsF2qCExphYptIQwM7pyBbJGSKOW1OS/VyMtmoBp
aUUWzU7MOffqnvOd0RocGJdXJ0BZgBihElOGqcgZz2iSSfIZvQ/QSjk42u5x9HxBV87BqXXhjT1W
Dbof5Vx1R3BePKO97aYvxryy76yz05Qzrd/U91/R/ZOXrm13Ut6KtuvNFfHizhYwbzl8moZ2cALl
Fd0NDh5K2xl4KKaTbTf/+rGdRtB1bb9758EpV/WuMqqeDDs1RzM/QgN9Ay5s/NLw4sbpsIMdxsf5
ju1eTNtpyEIeRuhPmcYjVnZofCxOfHEdjNU9qzfFhGEicyoyKTM217tde1UlivPIJJhqTbBgPMEJ
A4N5So0uk5iUUHj3GnrTVa2rbOPHbofaVW0NwdD0gxkz9uVQB7WHE6gZVR/YJjgcPqCnd+dXJM4v
tuOgHlt/c9BfxlrCHRRow8oEyxhiLFKRYM0Uw+OT4UrzSDGzgHu+udlt8t+hj/KRO2GZTP4ZPY3T
iy19O3VF+z+yj0JPP77M/kWqZ+gpY3/JXgoTEwoSCyFLLErgWEuRYiZTSZgwwhRyAfu724/r/eui
lykhl0tqzNsD/yvTIuy05CLmtMSp4BqLCAqsC1VgmUZxwUuhdUSXYN+tRug/Ab29GvHdBwAA
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "bruteforce" "cz.cesnet.nemea.brute_force_detector" "$in" "$out"

