# Demux module - README

## Description
This NEMEA module splits united input (by mux module) to more outputs

## Interfaces
- Input: 1
- Output: variable

## Parameters
### Module specific parameters
- `-n`             Sets count of output links. Must correspond to parameter -i (trap).

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm

- Module listens on the input interface. Based on the header info (interfaceID, data_fmt) splits united input to more outputs

