# Endiverter module - README

## Description
This NEMEA module switch byte order of fields in unirec messages received on input and forwards them to output interface.

## Interfaces
- Input: 1
- Output: 1

## Parameters
### Module specific parameters
- `-n`               Don't forward EOF message.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Fields of received unirec message are iterated and endianness is changed for those with the following types:

- `UINT16`
- `UINT32`
- `UINT64`
- `INT16`
- `INT32`
- `INT64`
- `FLOAT`
- `DOUBLE`
- `TIME`

and for metadata of the following types:

- `BYTES`
- `STRING`

Then the altered unirec message is sent to output interface.

## Use case
For instance, `endiverter` can be used when exporting and reading flow from `OpenWrt` router, where `OpenWrt`
uses different byte order.

```
   +----------------------+         +----------------------+
   |                      |         |                      |
   |        OpenWrt       |         |         linux        |
   |                      |         |                      |
   |         MIPS         |         |         x86          |
   |      big endian      |         |     little endian    |
   |                      |         |                      |
   |                      |         |                      |
   |   +--------------+   |         |   +--------------+   |
   |   |              |   |   msg   |   |              |   |
   |   |  flow_meter  +----------------->  endiverter  |   |
   |   |              |   |         |   |              |   |
   |   +--------------+   |         |   +-------+------+   |
   |                      |         |           |          |
   +----------------------+         | converted | msg      |
                                    |           |          |
                                    |   +-------v------+   |
                                    |   |              |   |
                                    |   |    logger    |   |
                                    |   |              |   |
                                    |   +--------------+   |
                                    |                      |
                                    +----------------------+
```

