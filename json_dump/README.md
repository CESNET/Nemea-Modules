# json_dump module - README

## Description
json_dump takes data from TRAP interface in JSON format and dumps it into stdout or file. It works as a "logger" for JSON interfaces.

## Interfaces
- Input: 1
- Output: 0

## Parameters
### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

### Module specific parameters
- `-w <filename>`        Write dump to FILE instead of stdout (overwrite file).
- `-a <filename>`        Write dump to FILE instead of stdout (append to file).
- `-I --indent <number>` Pretty-print JSON with indentation set to N spaces. Note that such format can't be read by json_replay module.
- `--noflush`            Disable automatic flush of output buffer after writing a record (may improve performance).

## Usage Examples
```
$ json_dump.py -i u:trap_in_ifc #write json to stdout
$ json_dump.py -i u:trap_in_ifc -w dest_file #write to file - overwrite mode
$ json_dump.py -i u:trap_in_ifc -a dest_file --noflush #write to file - append mode, disable autoflush
```
