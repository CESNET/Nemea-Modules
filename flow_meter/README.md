# Flow_meter module - README

## Description
This NEMEA module creates flows from input PCAP file / network interface and exports them to output interface.

## Interfaces
- Input: PCAP file or network interface
- Output interfaces: Unirec containing `<COLLECTOR_FLOW>` + fields added by active plugins

## Parameters
### Module specific parameters
- `-p STRING`        Activate specified parsing plugins. Output interface for each plugin correspond the order which you specify items in -i and -p param. For example: '-i u:a,u:b,u:c -p http,basic,dns\' http traffic will be send to interface u:a, basic flow to u:b etc. If you don't specify -p parameter, flow meter will require one output interface for basic flow by default. Format: plugin_name[,...] Supported plugins: http,dns,sip,basic
- `-c NUMBER`        Quit after `NUMBER` of packets are captured.
- `-I STRING`        Capture from given network interface. Parameter require interface name (eth0 for example).
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
When capturing from network interface, flows are continuously send to output interfaces until N (or unlimited number of packets if the -c option is not specified) packets are captured and exported.
