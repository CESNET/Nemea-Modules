# Unirecfilter module - README

## Description
This NEMEA module selects records according to parameters in filter and sends only fields specified in output template.

## Interfaces
- Input: 1
- Output: 1 - 32

## Parameters
### Module specific parameters
  - `-O TMPLT`  Specify UniRec template expected on the output interface.
    If you do not use template module will copy the template from input.
  - `-F FILTR`	Specify filter.
    If you do not use filter module will forward all incomming messages.
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

- `int8` 8bit signed integer
- `int16` 16bit signed integer
- `int32` 32bit signed integer
- `int32` 32bit signed integer
- `int64` 64bit signed integer
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
- `time` UniRec timestamp, such as `TIME_FIRST`, `TIME_LAST`. The time column can be compared with date&time specified in format: `YYYY-mm-ddTHH:MM:SS.sss`, where `.sss` represents miliseconds and is an optional part (Ex. `2018-01-10T21:17:00`). Note that the timestamp should be in UTC timezone.

**Subnets**

UniRec fields of `ipaddr` type (such as `SRC_IP`, `DST_IP`) can be compared with host IP addresses or with a subnet in the notation `IP/BITS`, where `BITS` represents
a number of leading '1' bits in the netmask.

Example: `-F "SRC_IP == 10.0.0.0/8"`

Note: `IP` need not to be necessarily a network address (it can be any IP address) because it is masked during the initiation of the filter (e.g., `10.1.1.1/8` becomes `10.0.0.0`).

Operator `==` returns true if and only if an `SRC_IP` belong to the given subnet.

### Format
#### Command line
Filter specified on command line with `-F` flag is a single expression which is evaluated for the output interface. For example: `-F "SRC_PORT == 23"`

#### File
Filter specified in a file provides more flexibility. Format of the file is `TEMPLATE_1:FILTER_1;...;TEMPLATE_N:FILTER_N;` where each semicolon separated item corresponds with one output interface. One-line comments starting with `#` are allowed. To reload filter while unirecfilter is running, send signal SIGUSR1 (10) to the process.

## Default values
You can use syntax FIELD=value in the template to specify default value used if field is not present on the input (f.e. uint32 BAR=1). Example bellow.
`./unirecfilter -i u:test_ifc_in,u:test_ifc_out -O "ipaddr SRC_IP, ipaddr DST_IP, uint16 SRC_PORT, uint16 DST_PORT, string MESSAGE=\"this_is_message\""`

## Usage
`./unirecfilter -i IFC_SPEC [-O TMPLT] [-F FLTR]`

`./unirecfilter -i IFC_SPEC [-f FILE]`

Here are some examples of running unirecfilter.
`./unirecfilter -i u:test_ifc_in,u:test_ifc_out -O "ipaddr SRC_IP, ipaddr DST_IP, uint16 SRC_PORT, uint16 DST_PORT"`
`./unirecfilter -i u:test_ifc_in,u:test_ifc_out -c 100 -F "SRC_PORT > 20"`
`./unirecfilter -i u:test_ifc_in,u:test_ifc_out -c 100 -O "ipaddr SRC_IP, ipaddr DST_IP, uint16 DST_PORT, uint16 SRC_PORT" -F "SRC_PORT == 443 || SRC_PORT == 53"`

Below is an example of config file "filter.txt" to be used with the -f parameter:
```
ipaddr DST_IP,ipaddr SRC_IP:SRC_PORT == 443; #port matching number 443
uint16 SRC_PORT:SRC_PORT >= 23 || DST_PORT >= 23; #usage of or
string BAR=not_present:BAR ~= "not_present"; #regex usage
```

You can then use filter file as shown below:
`unirecfilter -i u:test_ifc_in,u:test_ifc_out:timeout=HALF_WAIT,u:test_ifc_in,u:test_ifc_out2:timeout=HALF_WAIT -f "filter.txt"`

Especially notice interface option `:timeout=HALF_WAIT`. It will enable the module to run even for interfaces that are not listening. Meaning the module will not hang while waiting for someone to connect. It will drop the message and move on to sending next one. These dropped messages will count towart -c option (when this option is enabled).
