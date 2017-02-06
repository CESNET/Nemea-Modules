# Topn module - README

## Description
This NEMEA module computes various Top N statistics online. 

Module accepts UniRec records on it's input. According to -l <l> parameter it computes TOP-N statistics for the last <l> seconds for the <n> entities specified by -n <n> parameter for all flows and separately for specific ports specified by -p <port>[,<port>...] paremeter.

Types of statistics:

TOP-n IP addresses, which transferred most flows, packets, bytes
TOP-n prefixes, which transferred most flows, packets, bytes
TOP-n ports, through which most packets, bytes were transferred
TOP-n flows, which transferred most packets, bytes

## Interfaces
- Inputs: 0
- Outputs: 1

## Parameters
### Module specific parameters
- `-n N`	Number of entities for top N statistics.
- `-l L`	Length of time interval in seconds. Statistics are calculated upon this interval.
- `-p P1[,P2...]`	Specific ports upon which statistics will be calculated independently.
- `-m M1[,M2]`	Length of the prefix for IPv4 (M1) and IPv6 (M2).

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Accuracy
Top n ports and flows should be 100% accurate. Top n IPs and networks (prefixes) can differ from real results. This module aims to not use too much memory and since real online flows data contain a lot of information per second, some heuristics for computing statistics are used, which can result in less accurate results.

## Memory and speed
Each port from -p parameter costs additional memory and some speed. Bigger -n parameter does not necessary slow down main algorithm, but printing results can be slower. Module should use less than 20MB in basic setting (no -p or -m parameter used).

## Date
There will always be date printed before results, so that statistics for a certain time interval can be easily found (in a file,...). Date format is YYYY-MM-DD HH:MM:SS. For example, if parameter -l is 300 (5 minutes) and date before results is 2016-10-17 01:30:00, then this means that statistics are for interval between 2016-10-17 01:25:00 and 2016-10-17 01:30:00.

## Examples
1) ./topn -n 100 -l 300 -i "u:localhost:1234"
- basic setting, prints top 100 flows, ports and IPs each 5 minutes (300 seconds).

2) ./topn -n 50 -l 600 -m 16 -p 80 -i "u:localhost:1234"
- prints top 50 IPs, ports, IPv4 networks with /16 prefix and flows each 10 minutes. This gets printed again for port 80 (e.g. top 50 IPs which communicated through port 80, top ports which communicated most with port 80...)

3) ./topn -n 500 -l 1800 -m 8,72 -p 53,80,443 -i "u:localhost:1234"
- prints top 500 IPs, ports, IPv4 networks with /8 prefix, IPv6 networks with /72 prefix and flows each half an hour. This gets printed again for ports 53,80 and 443.

4) ./topn -n 10 -l 60 -m 32 -i "u:localhost:1234"
- when prefix /32 is set, there isn't basically any masking and top IPs should be same as top IPv4 networks


