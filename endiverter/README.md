# endiventer

## Description
This NEMEA module switch byte order of fields in unirec messages received on input and forwards them to output interface.

## Interfaces
- Input: 1
- Output: 1

## Parameters

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Fields of received unirec message are iterated and endianness is changed for the following fields: UINT16, UINT32,
UINT64, INT16, INT32, INT64, FLOAT, DOUBLE, TIME. Then the altered unirec message is send to output interface.

