## Exporter for Passive DNS

### Description

This module accepts DNS information in UniRec format on a TRAP interface.
Required information is provided either by the IPFixCol DNS plugin.
The output is JSON formated DNS data stored to file.

### Required data

Fields specified by IPFixCol DNS plugin

### JSON output

One record formated in JSON contains:
- `dns reponse`
- `dns query`
- `rr ttl`
- `rr type`
- `dns flow time_first`
- `dns flow time_last`

### Trap interfaces

- Inputs: 1
- Outputs: 0

### Parameters

See `python pdns_exporter.py -h` for help.

#### Exporter parameters
- `-t num`      Set number of JSON records per file

##### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

### How it works

Simple convertor from UniRec to JSON. Records formated in JSON are stored into files on disk.