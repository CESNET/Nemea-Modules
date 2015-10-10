# Unirecfilter module - README

## Description
This NEMEA module selects records according to parameters in filter and sends only fields specified in output template.

## Interfaces
- Input: 1
- Output: variable

## Parameters
### Module specific parameters
  - `-O TMPLT`  Specify UniRec template expected on the output interface.
  - `-F FILTR`	Specify filter.
  - `-f FILE`	Read template and filter from FILE.
  - `-c N`		Quit after N records are received.

### Common TRAP parameters
- `-h [trap,1]`        Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Filter
Filter is a logical expression composed of terms joined together by logical operators, possibly with the use of brackets. Term is a triplet `unirec_field cmp_operator value`, e.g. FOO == 1. 

### Operators
Available comparison operators are:

- `>` greater than
- `<` lesser than
- `>=`, `=>` greater than or equal
- `<=`, `=<` lesser than or equal
- `=`, `==` equal
- `!=`, `<>` not equal
- `=~`, `~=` matches regular expression

Available logical operators are:

- `||`, `OR` - or
- `&&`, `AND` - and
- `!`, `NOT` - not

### Data types

Almost all data types from unirec are supported:

- `int8` 8bit singed integer
- `int16` 16bit singed integer
- `int32` 32bit singed integer
- `int32` 32bit singed integer
- `int64` 64bit singed integer
- `uint8` 8bit unsigned integer
- `uint16` 16bit unsigned integer
- `uint32` 32bit unsigned integer
- `uint64` 64bit unsigned integer
- `char`  a single ASCII character
- `float` single precision floating point number (IEEE 754)
- `double` double precision floating point number (IEEE 754)
- `ipaddr` special type for IPv4/IPv6 addresses, see unirec README (note -  IPv6 address in a filter loaded from a file has to be surrounded by double quotes because of syntax issues)
- `string` variable-length array of (mostly) printable characters, surrounded by double quotes
- `bytes` variable-length array of bytes (not expected to be printable characters), surrounded by double quotes

### Format
#### Command line
Filter specified on command line with `-F` flag is a single expression which is evaluated for the output interface.

#### File
Filter specified in a file provides more flexibility. Format of the file is `[TEMPLATE_1]:FILTER_1;...;[TEMPLATE_N]:FILTER_N;` where each semicolon separated item corresponds with one output interface. One-line comments starting with `#` are allowed. To reload filter while unirecfilter is running, send signal SIGUSR1 (10) to the process.

## Default values
You can use syntax FIELD=value in the template to specify default value used if field is not present on the input (f.e. uint32 BAR=1)

## Usage
`./unirecfilter -i IFC_SPEC [-O TMPLT] [-F FLTR]`

`./unirecfilter -i IFC_SPEC [-f FILE]`
