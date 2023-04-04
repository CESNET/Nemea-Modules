# json_replay module - README

## Description
json_replay loads JSON data from a file (in json-per-line format) and sends it over a TRAP interface to another module.
It can replay data stored by json_dump to a file.

## Interfaces
- Input: 0
- Output: 1

## Parameters
### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

### Module specific parameters
- `-f --format <format>`  Set format identifier string (this must match the format ID required by receiving module)
- `-n --no-eos`           Don't send end-of-stream message at the end.

## Usage Examples
```
# read data from 'file.json' and send them to unix socket interface named 'trap_ifc'
$ json_replay.py -i u:trap_out_ifc < file.json

# if the receiving module requires a specifc JSON format, set the format identifier accordingly (here "my_json_format")
$ json_replay.py -i u:trap_in_ifc -f "my_json_format" < file.json
```
