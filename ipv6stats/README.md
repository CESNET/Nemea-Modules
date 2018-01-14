# IPv6stats module - README

## Table of Contents
    1. Module description
    2. Interfaces
    3. Parameters
    4. Output files
    5. How to use

## 1. Module description
Module gathers an IPv6 (mainly) statistic from a traffic. These statistics
are printed into the output files: traffic, ipv6_tunnels, cnt_addr, cnt_addr_L.
Module expects the input records in the UniRec format
"<COLLECTOR_FLOW>,IPV6_TUN_TYPE". Statistics are collected for a short and
long window. Size of the long window should be multiple of size of the short
window. By default the size of the short window is 5 minutes, the size of the
long window is 1 hour.

Following statistics are gathered:
* For the short/long window
   - count of unique IPv4 addresses, which generated at least K packets
   - count of unique IPv6 addresses, which generated at least K packets
   - count of unique IPv6 /64 prefixes, which generated at least K packets
   - count of unique IPv6 /48 prefixes, which generated at least K packets
K is the threshold (tune-able by parameter).
* For the short window only
   - count of flow/packet/byte for IPv4 and IPv6
   - count of flow/packet/byte for every IPv6 tunnel type
Supported tunnel types: native IPv6, Teredo, 6to4, Protocol 41, ISATAP, AYIYA,
6over4. Count of flow/packet/byte are expressed as values per second in output
files.

The output files stores values only for the last window (short/long).

## 2. Interfaces
Input: 1 UniRec record in format: "<COLLECTOR_FLOW>,IPV6_TUN_TYPE"
Output: 0

## 3. Parameters
   -d <path> - the path to the output files, path string have to by ended by the
               slash symbol. The default path is "".
   -n        - (no value) turns off storing of the statistics from the last
               (incomplete) window on exit. This is turned on by default.
   -l <sec>  - the size of the long window in seconds. The default value is
               12*<default_size_of_short_window>.
   -L <N>    - the size of the long window as multiple of the size of the short
               window. This´parameter has higher priority then parameter -l.
   -p <K>    - the threshold for covering an element into the unique statistics.
               An element have to generate at least <K> packets to be covered
               into the unique statistics ( >= <K>). The default value is 1.
   -s <sec>  - the size of the short window in seconds. The default value is
               300.

## 4. Output files
File(s) name(s) for the statistics from long window are ended by prefix _L.
Format of these output files do not differs from the format of the files from
the short window.

### File cnt_addr (cnt_addr_L)
Contains counts of unique addresses (IPv4/IPv6) and IPv6 prefixes (48/64).
Format of the file(s) is:

ipv4 123
ipv6 123
ipv6_48 123
ipv6_64 123
updated 2014-01-16.15:31:40

### File ipv6_tunnels
Contains counts of packets/bits/flows (columns corresponds to this order) per
second for every IPv6 tunnel type. Format of the file is:

Native 240 2504130 901
Teredo 18878159 14291516 3276
ISATAP 545 37060 142
6to4 62149 924764 4320
AYIYA 0 0 0
Proto41 5089 418667 1972
6over4 19 2500 11
updated 2014-01-16.15:31:40

### File traffic
Contains counts of packets/bits/flows (columns corresponds to this order) per
second for IPv4 and IPv6 addresses. Format of the file is:

ipv4 123 1234 12
ipv6 123 1234 12
updated 2014-01-16.15:31:40

## 5. How to use
./ipv6stats -i "t;localhost,7605" -n -p 3 -d /data/ipv6stats/

This will starts ipv6stats module, expecting input data on TCP port 7605, last
(incomplete) stats will not be flushed on exit, unique statistics will be made
from records with packets > 3 and statistics will be stored in
"/data/ipv6stats/" folder.