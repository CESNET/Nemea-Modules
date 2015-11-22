# Flow_meter module - README

## Description
This NEMEA module creates flows from input PCAP file / network interface and exports them to output interface.

## Interfaces
- Input: PCAP file or network interface
- Output interface: Unirec containing `<COLLECTOR_FLOW>` + fields added by active plugins

## Parameters
### Module specific parameters
- `-p STRING`        Activate specified parsing plugins. Format: plugin_name[,...] Supported plugins: http
- `-c NUMBER`        Quit after N packets are captured.
- `-I STRING`        Name of network interface to capture from. (eth0 for example)
- `-r STRING`        Pcap file to read.
- `-t NUM:NUM`       Active and inactive timeout in seconds. (DEFAULT: 300.0:30.0)
- `-s NUMBER`        Size of flow cache in number of flow records. Each flow record has 232 bytes. (DEFAULT: 65536)
- `-S NUMBER`        Print statistics. `NUMBER` specifies interval between prints.
- `-m NUMBER`        Sampling probability. `NUMBER` in 100 (DEFAULT: 100)
- `-V STRING`        Replacement vector. 1+32 NUMBERS.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Stores packets from input PCAP file / network interface in flow cache to create flows. After whole PCAP file is processed, flows from flow cache are exported to output interface.
When capturing from network interface, flows are continuously send to output interface until N (or unlimited number of packets if the -c option is not specified) packets are captured and exported.
