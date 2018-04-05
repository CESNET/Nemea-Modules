# Mux module - README

## Description
This NEMEA module unites more input interfaces into one output interface

## Interfaces
- Input: variable
- Output: 1

## Parameters
### Module specific parameters
- `-n`             Sets count of input links. Must correspond to parameter -i (trap).

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm

- Each thread listens on one input interface and forwards received data via one raw output interface. 
- To recover united traffic use demux NEMEA module.
- Received data are encapsulated into payload. Metadata for demultiplexing are in the header (interfaceID, data_fmt).
