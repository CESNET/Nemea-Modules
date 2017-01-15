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
- Inputs: 1
- Outputs:

## Parameters
### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Module agregates information about L4 protocol used in flows. It creates unix socket (/tmp/prot_flows.sock) and sends current protocol statistics to any connected client.

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

## Install Munin script

1) Install the example module

2) Run the module

3) Change appropriately owner and rights of created unix socket file.

4) Copy the script into /usr/share/munin/plugins/munin_prot_flows.

5) Create symbolic link: ln -s /usr/share/munin/plugins/munin_prot_flows /etc/munin/plugins/

6) Restart munin-node service: service munin-node restart