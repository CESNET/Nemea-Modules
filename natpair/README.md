# NATpair Module

## Table of Contents

* [Module description](#module-description)
* [How it works](#how-it-works)
* [Required data](#required-data)
* [Output data](#output-data)
* [How to use](#how-to-use)
* [Compilation and linking](#compilation-and-linking)

## Module description

NATpair module is intended for pairing flows from LAN and WAN which undergone the Network address translation (NAT) process.

## How it works

NATpair module uses two threads (one for each input interface) which receive data from LAN and WAN. 
Partial flows (part from LAN or WAN only) which are routed from LAN to WAN or WAN to LAN are subsequntly stored into a queue.
Another thread pops data from the queue and attempts to find the rest of the flow in a hash map.

Two partial flows match when the following conditions are met:

 - the scope of both flows differs (one is LAN, the other is WAN)
 - the direction of both flows is the same (L2W or W2L)
 - external host IP address of both flows is the same
 - external host port of both flows is the same
 - the protocol used in both flows is the same
 - time of the first packet of the flow differs only slightly in both flows
 - time of the last packet of the flow differs only slightly in both flows

If a match is found, then information about the whole flow is sent to the output interface and removed from the hash map.
If a match is not found, the partial flow is stored in the hash map.

The whole hash map is occasionally cleared of incomplete flows which are stored longer than allowed (the value is adjustable).

## Required data

This module is implemented on TRAP platform, so it receives data on
TRAP input interface in UniRec format.

UniRec fields required:

 - DST\_IP (ipaddr): destination IP address of the flow
 - SRC\_IP (ipaddr): source IP address of the flow
 - DST\_PORT (uint16): destination port of the flow
 - SRC\_PORT (uint16): source port of the flow
 - PROTOCOL (uint8): protocol used (TCP, UDP...)
 - TIME\_FIRST (time): time of the first packet in the flow
 - TIME\_LAST (time): time of the last packet in the flow

## Output data

Flows sent to the output interface are in UniRec format. Each record contains the following UniRec fields:

 - LAN\_IP (ipaddr): IP address of the client in LAN
 - RTR\_IP (ipaddr): IP address of the WAN interface of the router performing NAT process
 - WAN\_IP (ipaddr): IP address of the host in WAN
 - LAN\_PORT (uint16): port of the client in LAN
 - RTR\_PORT (uint16): port on the WAN interface of the router performing NAT process
 - WAN\_PORT (uint16): port of the host in LAN
 - TIME\_FIRST (time): time of the first packet in the flow
 - TIME\_LAST (time): time of the last packet in the flow
 - PROTOCOL (uint8): protocol used (TCP, UDP...)
 - DIRECTION (uint8): 0 stands for LAN to WAN, 1 stands for WAN to LAN

## How to use

Since this module uses TRAP, input and output interfaces need to be specified.

Usage:

```
./natpair -i <trap_interfaces> <Additional parameters>
```

Additional parameters:

    -c <uint32>	Frequency of flow cache cleaning. [sec] (default: 600s)

    -f <uint32>	Maximum time for which unpaired flows can remain in flow cache. [sec] (default: 5s)

    -r <string> IPv4 address of WAN interface of the router which performs the NAT process.

    -s <uint32>	Number of elements in the flow cache which triggers cache cleaning. (default: 2000)

Parameter **-r** must always be specified.

Example:

```
./natpair -i "u:lan_data_source,w:lan_data_source,f:~/paired_flows.trapcap" -r "147.32.233.150" -c 600 -f 60 -s 5000
```

## Compilation and linking

This module requires compilation with -std=c++11, because of the usage of *std::unordered_map*.

For linking add -ltrap -lunirec
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).
