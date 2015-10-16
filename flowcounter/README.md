# Flowcounter module - README

## Description
This NEMEA module counts number of incoming flow records.

## Interfaces
- Input: UniRec format specified by template from `-u` parameter.
- Output: none or `@VOLUME` record, affected by `-o` parameter.

## Parameters
### Module specific parameters
- `-u TMPL` Specify UniRec template expected on the input interface.
- `-p N`	Show progress bar - print a dot every N flows.
- `-P CHAR`	When `-p` parameter is enabled, print CHAR instead of dot.
- `-o SEC`	Send `@VOLUME` record filled with current counters every SEC second (s). Interval for SEC is (0;1000).

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.
