# Link_traffic module - README

## Description
This module processes flow data (sums flows, bytes, packets for each LINK_BIT_FIELD). Munin plugin then connects to it via UNIX socket to create graphs.

## Interfaces
- Input: 1
- Output: 0

## Parameters
### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Module collects statistics about flows according to LINK_BIT_FIELD. Running module creates a UNIX socket (/var/run/libtrap/munin_link_traffic). Munin plugin then connects to this socket and gets formatted string with data. The format is the following (the number of headers is not limited):

```
"header1, header2, header3\n
value1, value2, value3"
```
When munin plugin starts it checks /tmp/munin_link_traffic_data.txt. If it is actual enough it uses cached data, if its not actual it connects to UNIX socket and creates new cache file.

## Install Munin script

In order to get data into munin server you need to set it up. Easies way is to execute suggested commands to activate graphs you want: `munin-node-configure --suggest --shell`

When the confituration is done you need to restart munin-node service: `service munin-node restart`
