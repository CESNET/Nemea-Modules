# Merger module - README

## Description

This module merges traffic from multiple input interfaces to one
output stream (on one interface).

## Interfaces

- Input: variable, one UniRec record in format

- Output: 1, same UniRec format as input.

## Parameters
### Module specific parameters

- `-u FMT` or `--unirec FMT` UniRec specifier of input/output data
  (same to all links, default is <COLLECTOR_FLOW>).

- `-n` or `--noeof` Do not send termination message.

- `-I` or `--ignore-in-eof` Do not terminate on incoming termination
  message.

### Common TRAP parameters

- `-h [trap,1]` Print help message for this module / for libtrap
  specific parameters.

- `-i IFC_SPEC` Specification of interface types and their parameters.

- `-v` Be verbose.

- `-vv` Be more verbose.

- `-vvv` Be even more verbose.

## Usage

`./merger -i "t:localhost:8801,t:localhost:8802,t:localhost:8803,t:localhost:8804,u:DNS_out" -u "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint32 DNS_RR_TTL,uint16 DNS_ANSWERS,uint16 DNS_CLASS,uint16 DNS_ID,uint16 DNS_PSIZE,uint16 DNS_QTYPE,uint16 DNS_RLENGTH,uint16 DST_PORT,uint16 SRC_PORT,uint8 DNS_DO,uint8 DNS_RCODE,uint8 PROTOCOL,string DNS_NAME,bytes DNS_RDATA"`

This command will start merger with 4 inputs (on localhost, TCP ports
8801 - 4), output stream on Unix socket "DNS_out", with UniRec
template given by listed fields.
