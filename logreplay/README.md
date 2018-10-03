# Logreplay module - README

## Description

This module converts CSV format of data, from logger module to UniRec
format and sends it to the output interface. Input CSV format is
expected to have UniRec specifier on the first line (logger parameter
-t).

## Interfaces

- Input: 0
- Output: 1 (UniRec; format depends on first line in CSV, which
  specifies types of stored fields)

## Parameters
### Module specific parameters
- `-f FILE` File containing CSV data from logger module.
- `-c N` 	Quit after N records are sent.
- `-n` 		Do not send "EOF message" at the end.

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.
