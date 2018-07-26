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

This module converts a particular UniRec fields specified by DNS plugin and
prints them in a specific JSON that is expected on Passive DNS.
Modul stoter JSON records into files and then moves files to specified location.

Example how JSON output could look like:
```
[{
    "response": "209.15.26.178",
    "query": "api.surfeasy.com",
    "ttl": 120,
    "type": 1,
    "time_first": "2018-07-18T08:13:58.042000",
    "time_last": "2018-07-18T08:13:58.042000"
}]
```