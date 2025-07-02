Prefix Tags Module
==================

This module adds "tags" to UniRec records based on src/dst ip prefix specified
in the configuration file.

The intention of this module is to unify configuration and simplify prefix
matching for modules that need to work on multiple IP prefixes.

This module adds `PREFIX_TAG` value to output UniRec records based on `SRC_IP`
and/or `DST_IP` fields based on configuration file.


Interfaces
----------

- Input: One UniRec interface
  - Template *MUST* contain fields `SRC_IP` or `DST_IP` (see cli options).
- Output: One UniRec interface
  - Output template is copied from input template with `PREFIX_TAG` and `PREFIX_TAG_DST` fields added.
  - The module sends only records with matched prefix.


Usage
-----

```
TRAP module, libtrap version: 0.12.0 
===========================================
Name: prefix_tags
Inputs: 1
Outputs: 1
Description:
  This module adds PREFIX_TAG field to the output acording to configured ip prefixes.

Usage:  prefix_tags [COMMON]... [OPTIONS]... 

Parameters of module [OPTIONS]:
-------------------------------
  -c  --config <string>   Configuration file.
  -d  --dst               Use only DST_IP field for prefix matching (default is both SRC_IP and DST_IP).
  -s  --src               Use only SRC_IP field for prefix matching (default is both SRC_IP and DST_IP).
  -b  --both              Both SRC_IP and DST_IP is tagged. When -b is not enabled, the `PREFIX_TAG_DST` is always `0` and only PREFIX_TAG field is used
Common TRAP parameters [COMMON]:
--------------------------------
  -h [trap,1]             If no argument, print this message. If "trap" or 1 is given, print TRAP help.
  -i IFC_SPEC             Specification of interface types and their parameters, see "-h trap" (mandatory parameter).
  -v                      Be verbose.
  -vv                     Be more verbose.
  -vvv                    Be even more verbose.

Environment variables that affects output:
------------------------------------------
  LIBTRAP_OUTPUT_FORMAT   If set to "json", information about module is printed in JSON format.
  PAGER                   Show the help output in the set PAGER.
  TRAP_SOCKET_DIR         Change path to socket directory (default: /var/run/libtrap).
```

__NOTE__: By default both `SRC_IP` and `DST_IP` are being matched against configured
IP prefixes. In case both `SRC_IP` and `DST_IP` match some configured prefix,
`SRC_IP` is preferred.

Configuration
-------------

See `example_config.json`.


Key description:
- `id` - Used as `PREFIX_TAG` value
- `ip_prefix` - IP prefix used to match `SRC_IP`/`DST_IP` in incoming records
    - If `ip_prefix` specified are overlapping, first one will be used.
    - Warning: IP addresses must be followed by netmask, e.g., `"10.0.0.0/8"`.


- JSON keys not used by this module are ignored and will __not rise error__!
- Compatible with `bloom_history` module configuration


Future development
------------------

This module is considered to be feature complete.

