# json_replay module - README

## Description
json_replay is able to load data from JSON file and send it over a TRAP interface to other module. Therefore you cant send files stored by json_dump to your desired module or reporter - data is sent in JSON format.

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
#read data from file.json and send them to trap_out_ifc
$ json_replay.py -i u:trap_out_ifc < file.json

#data send with format to recieve by module with required format set to "DST_IP, SRC_IP"
$ json_replay.py -i u:trap_in_ifc -f "DST_IP, SRC_IP"
```
