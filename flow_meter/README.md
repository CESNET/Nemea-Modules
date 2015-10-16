# Flow_meter module - README

## Description
This NEMEA module creates flows from input PCAP file and exports them to output interface.

## Interfaces
- Input: PCAP file
- Output interface: Unirec containing `<COLLECTOR_FLOW>`

## Parameters
### Module specific parameters

- `-r FILENAME`       Pcap file to read.
- `-t NUM:NUM`        Active and inactive timeout in seconds. (DEFAULT: 300.0:30.0)
- `-p NUMBER`         Collect payload of each flow. `NUMBER` specifies a limit to collect first `NUMBER` of bytes. By default do not collect payload.
- `-s NUMBER`         Size of flow cache in number of flow records. Each flow record has 232 bytes. (DEFAULT: 65536)
- `-S NUMBER`         Print statistics. `NUMBER` specifies interval between prints.
- `-m NUMBER`         Sampling probability. `NUMBER` in 100 (DEFAULT: 100)
- `-v STRING`         Replacement vector. 1+32 NUMBERS.

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Stores packets from input PCAP file in flow cache to create flows. After whole PCAP file is processed, flows from flow cache are exported to output interface.