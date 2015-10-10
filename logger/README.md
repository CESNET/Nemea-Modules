# Logger module - README

## Description
This NEMEA module logs incoming UniRec records into stdout or into specified file(s).

## Interfaces
- Input: variable
- Output: 0

## Parameters
### Module specific parameters
- `UNIREC_FMT`  The i-th parameter of this type specifies format of UniRec expected on the i-th input interface.
- `-w FILE`        Write output to FILE instead of stdout (rewrite the file).
- `-a FILE`        Write output to FILE instead of stdout (append to the end).
- `-o OUT_FMT`     Set of fields included in the output (UniRec specifier). Union of all input formats is used by default.
- `-t`             Write names of fields on the first line.
- `-T`             Add the time when the record was received as the first field.
- `-n`             Add the number of interface the record was received on as the first field (or second when -T is specified).
- `-c N`           Quit after N records are received.
- `-d X`           Optionally modifies delimiter to inserted value X (implicitely ','). Delimiter has to be one character long, except for printable escape sequences.

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm

-  Each record is written as one line containing values of its fields in human-readable format separated by chosen delimiters (CSV format).
-  Number of input intefaces and their UniRec formats are given on command line (if you specify N UniRec formats, N input interfaces will be created).
-  Output contains union of all fields of all input formats by default, but it may be redefined using -o option.