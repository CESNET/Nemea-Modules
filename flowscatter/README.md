# Example module - README

## Installation
Follow these steps:

1) Let Autotools process the configuration files.
```
autoreconf -i
```

2) Configure the module directory.
```
./configure
```

3) Build the module.
```
make
```

4) Install the module. The command should be performed as root (e.g. using sudo).
```
make install
```

Important: Nemea-Framework has to be compiled (or installed) in advance.

## Description
This module contains example of module implementation using TRAP platform.

## Interfaces
- Inputs: 0
- Outputs: 1

## Parameters
### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Module recives UniRec format containing two numbers FOO and BAR. Sends UniRec format containing FOO, BAR and their sum as BAZ.

## Troubleshooting
### Loading shared libraries
In case the example module fails with:
```
error while loading shared libraries: libtrap.so.1: cannot open shared object file: No such file or directory
```
please, make sure that libtrap is installed on the system.
It is also possible to use libtrap that is not installed yet -- in this case, use:
```
export LD_LIBRARY_PATH=../../libtrap/src/.libs/
```
where `../../libtrap/src/.libs/` is the relative path from the `examples/module` directory in the downloaded and compiled Nemea-Framework repository.

### TRAP parameters
In case the example module fails with:
```
ERROR in parsing of parameters for TRAP: Interface specifier (option -i) not found.
```
It means you haven't provided the parameters required by the TRAP library. For more information run the module with `-h trap` parameter.