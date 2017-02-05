# Flow_meter module - README

## Description
This NEMEA module creates flows from input PCAP file / network interface and exports them to output interface.

## Requirements
- To compile this module you will need [libpcap](http://www.tcpdump.org/) development library installed.
- Root priviliges are needed when capturing from network interface.

## Interfaces
- Input: PCAP file or network interface
- Output interfaces: Unirec containing `<COLLECTOR_FLOW>` + fields added by active plugins

## Parameters
### Module specific parameters
- `-p STRING`        Activate specified parsing plugins. Output interface for each plugin correspond the order which you specify items in -i and -p param. For example: '-i u:a,u:b,u:c -p http,basic,dns\' http traffic will be send to interface u:a, basic flow to u:b etc. If you don't specify -p parameter, flow meter will require one output interface for basic flow by default. Format: plugin_name[,...] Supported plugins: http,dns,sip,ntp,basic,arp
- `-c NUMBER`        Quit after `NUMBER` of packets are captured.
- `-I STRING`        Capture from given network interface. Parameter require interface name (eth0 for example).
- `-r STRING`        Pcap file to read. `-` to read from stdin.
- `-n`               Don't send eof when flow_meter exits.
- `-l NUMBER`        Snapshot length when reading packets. Set value between `120`-`65535` .
- `-t NUM:NUM`       Active and inactive timeout in seconds. Format: DOUBLE:DOUBLE. Value default means use default value 300.0:30.0.
- `-s STRING`        Size of flow cache in number of flow records. Each flow record has 176 bytes. default means use value 65536.
- `-S NUMBER`        Print flow cache statistics. `NUMBER` specifies interval between prints.
- `-P`               Print pcap statistics every 5 seconds. The statistics do not behave the same way on all platforms.
- `-L NUMBER`        Link bit field value.
- `-D NUMBER`        Direction bit field value.
- `-F STRING`        String containing filter expression to filter traffic. See man pcap-filter.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Stores packets from input PCAP file / network interface in flow cache to create flows. After whole PCAP file is processed, flows from flow cache are exported to output interface.
When capturing from network interface, flows are continuously send to output interfaces until N (or unlimited number of packets if the -c option is not specified) packets are captured and exported.

## Extension
`flow_meter` can be extended by new plugins for exporting various new information from flow.
There are already some existing plugins that export e.g. `DNS`, `HTTP`, `SIP`, `NTP`.

## Adding new plugin
To create new plugin use [create_plugin.sh](create_plugin.sh) script. This interactive script will generate .cpp and .h
file template and will also print `TODO` guide what needs to be done.

## Exporting packets
It is possible to export single packet with additional information using plugins (`ARP`).

## Possible issues
### Flows are not send to output interface when reading small pcap file
Turn off message buffering using `buffer=off` option on output interfaces.

```
./flow_meter -i u:abc:buffer=off -r traffic.pcap
```

## Simplified function diagram
Diagram below shows how `flow_meter` works.

1. `Packet` is read from pcap file or network interface
2. `Packet` is processed by PcapReader and is about to put to flow cache
3. Flow cache create or update flow and call `pre_create`, `post_create`, `pre_update`, `post_update` and `pre_export` functions for each active plugin at appropriate time
4. `Flow` is put into exporter when considered as expired, flow cache is full or is forced to by a plugin
5. Exporter fills `unirec record`, which is then send it to output libtrap interface

```
       +--------------------------------+
       | pcap file or network interface |
       +-----+--------------------------+
             |
          1. |
             |                                  +-----+
    +--------v---------+                              |
    |                  |             +-----------+    |
    |    PcapReader    |      +------>  Plugin1  |    |
    |                  |      |      +-----------+    |
    +--------+---------+      |                       |
             |                |      +-----------+    |
          2. |                +------>  Plugin2  |    |
             |                |      +-----------+    |
    +--------v---------+      |                       |
    |                  |  3.  |      +-----------+    +----+ active plugins
    |   NHTFlowCache   +------------->  Plugin3  |    |
    |                  |      |      +-----------+    |
    +--------+---------+      |                       |
             |                |            .          |
          4. |                |            .          |
             |                |            .          |
    +--------v---------+      |                       |
    |                  |      |      +-----------+    |
    |  UnirecExporter  |      +------>  PluginN  |    |
    |                  |             +-----------+    |
    +--------+---------+                              |
             |                                  +-----+
          5. |
             |
       +-----v--------------------------+
       |    libtrap output interface    |
       +--------------------------------+
```
