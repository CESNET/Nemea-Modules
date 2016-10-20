# Nfdump Reader Module - README

## Description
The NEMEA module reads nfdump files and sends flow records in UniRec format on its output TRAP interface. A filter in the same format as nfdump uses may be applied to filter flow records. If more files are specified, all flows from the first file are read, then all flows from second file and so on.

## Interfaces
- Input: 0
- Output: 1 (`<COLLECTOR_FLOW>`)

## Parameters
### Module specific parameters
- `FILE` 	   A file in nfdump format.
- `-f FILTER`	A nfdump-like filter expression. Only records matching the filter will be sent to the output. 
- `-c N`		   Read only the first `N` flow records.
- `-n` 		   Do not send "EOF message" at the end.
- `-T`		   Replace original timestamps by record actual sending time.
- `-l m` 	   Use link mask m for `LINK_BIT_FIELD`. m is 8-bit hexadecimal number.
- `-p N`		   Show progress - print a dot every `N` flows.
- `-r N`		   Rate limiting. Limiting sending flow rate to `N` records/sec.
- `-R`		   Real time re-sending. Re-sending records from given files in real time, respecting original timestamps (seconds). Since this mode is timestamp order dependent, real time re-sending is done only at approximate time.

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Usage
`./nfdump_reader -i IFC_SPEC [-f FILTER] [-c N] [-n] FILE [FILE...]`

- _Note: In output format, not all fields are filled!_
