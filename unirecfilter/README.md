# Unirecfilter README

## Goal
This NEMEA module selects records according to parameters in filter and sends only fields specified in output template.
	
## Interfaces
- **Input interface:** 1
- **Output interface:** variable

## Parameters
  - `-O TMPLT`	Specify UniRec template expected on the output interface.
  - `-F FILTR`	Specify filter.
  - `-f FILE`	Read template and filter from FILE.
  - `-c N`		Quit after N records are received.

## Filter
Filter is a logical expression which is usually composed of the name of a field, a logical operator and a value, e.g. FOO == 32.

### Command line
Filter specified on command line with `-F` flag is a single expression which is evaluated for the output interface. 

### File
Filter specified in a file provides more flexibility. Format of the file is `[TEMPLATE_1]:FILTER_1; ...; [TEMPLATE_N]:FILTER_N;` where each semicolon separated item corresponds with one output interface. One-line comments starting with `#` are allowed. To reload filter while unirecfilter is running, send signal SIGUSR1 (10) to the process.

### Operators
Supported operators are:

- comparisson: `>, <, =<, <=, >=, =>`
- equality: `=, ==, !=, <>, =~, ~=`
- logical: `!, NOT, ||, OR, &&, AND`

## Default values
You can use syntax FIELD=value in the template to specify default value used if field is not present on the input (f.e. uint32 BAR=1)

## Usage
`./unirecfilter -i IFC_SPEC [-O TMPLT] [-F FLTR]`

`./unirecfilter -i IFC_SPEC [-f FILE]`
