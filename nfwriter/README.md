# nfwriter - README

## Description
This module reads flow records in UniRec format from its input TRAP interface and writes them to nfdump file.

## Interfaces
- Input: 1 (`<COLLECTOR_FLOW>`)
- Output: 0

## Parameters
### Module specific parameters
- `-f FILE`    Output nfdump file.
- `-a`         Append output to file.
- `-b`         Compress with bz2.
- `-l`         Compress with lzo.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Notes
- You will need `libnf` library in order to compile this module.

