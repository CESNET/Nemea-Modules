# Merger module - README

## Description
This module merges traffic from multiple input interfaces to one output stream
(on one interface). There are two supported versions:

- normal (default) - re-sending incoming data as they come.
- timestamp aware - incoming data are sent with respect to timestamp order. Sorting is very simple, sends record with the latest timestamp. If record with more late timestamp is received, it is resent immediately. There are one thread for every input interface.

## Interfaces
- Input: variable, one UniRec record in format (passed as parameter)
- Output: 1, same UniRec format as input.

## Parameters
### Module specific parameters
- `-n CNT`  Sets count of input links. Must correspond to parameter -i (trap).
- `-T`      Set mode to timestamp aware (not set by default).
- `-u FMT`  UniRec specifier of input/output data (same to all links, default is <COLLECTOR_FLOW>).

Timestamp aware version only:

- `-F`      Sorts timestamps based on `TIME_FIRST` field, instead of `TIME_LAST` (default).
- `-t MS`   Set initial timeout for incoming interfaces (in seconds). Timeout is set to 0, if no data received in initial timeout (default 1s).

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Usage
`./merger -i "t:localhost:8801,t:localhost:8802,t:localhost:8803,t:localhost:8804,u:DNS_out" -n 4 -u "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint32 DNS_RR_TTL,uint16 DNS_ANSWERS,uint16 DNS_CLASS,uint16 DNS_ID,uint16 DNS_PSIZE,uint16 DNS_QTYPE,uint16 DNS_RLENGTH,uint16 DST_PORT,uint16 SRC_PORT,uint8 DNS_DO,uint8 DNS_RCODE,uint8 PROTOCOL,string DNS_NAME,bytes DNS_RDATA"`

This command will start merger with 4 inputs (on localhost, TCP ports 8801 - 4), output stream on Unix socket "DNS_out", with UniRec template given by listed fields.
