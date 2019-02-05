Blooming history module
=======================

This module aggregates information about entities (identified using IP address)
communicating with protected prefix, stores them in a [bloom filter][1] and after
given interval sends them to specified service using HTTP POST.

The intended usage is that the service stores the filters. When the time is
right (e.g. a DDoS attack incoming) the service further aggregates the stored
bloom filters received in a longer period of time and sends the result to a DDoS
mitigation device (e.g. CESNET DMD, Linux machine). The device can then filter
based on the addresses "white-listed" in the aggregated filter.

Given that the bloom filter should contain addresses of "well behaved" entities,
some filtering might be necessary (e.g. using `unirecfilter` module).

See [original whitepaper][2] by which this module is inspired.

This module adds the `DST_IP` is added to the bloom filter corresponding to the
`PREFIX_TAG` specified in the configuration file.


Interfaces
----------

- Input: One UniRec interface
  - Template *MUST* contain `DST_IP` and `PREFIX_TAG` (see
    `prefix_tags` module) fields.


Usage
-----

```
TRAP module, libtrap version: 0.12.0 
===========================================
Name: bloom_history
Inputs: 1
Outputs: 0
Description:
  This module gathers history of communicating entities and stores them in a bloom filter.
  
Usage:  bloom_history [COMMON]... [OPTIONS]... 

Parameters of module [OPTIONS]:
-------------------------------
  -c  --config <string>    Configuration file.
  -t  --interval <int32>   Interval in seconds, after which an old Bloom filter is sent to the Aggregator service and replaced by a new empty filter.

Common TRAP parameters [COMMON]:
--------------------------------
  -h [trap,1]              If no argument, print this message. If "trap" or 1 is given, print TRAP help.
  -i IFC_SPEC              Specification of interface types and their parameters, see "-h trap" (mandatory parameter).
  -v                       Be verbose.
  -vv                      Be more verbose.
  -vvv                     Be even more verbose.
  
Environment variables that affects output:
------------------------------------------
  LIBTRAP_OUTPUT_FORMAT    If set to "json", information about module is printed in JSON format.
  
  PAGER                    Show the help output in the set PAGER.
  
  TRAP_SOCKET_DIR          Change path to socket directory (default: /var/run/libtrap).
```

__NOTE__: The `--interval` is common for all configured prefixes.


Installation
------------

For this module to be compiled you need:

- `libpthread`
- `libcurl`

This module also uses `libbloom` and includes its slightly modified sources in
`libbloom/` directory. The upstream project can be found at [GitHub][3].


Configuration
-------------

Key description:

- `id` - Used as `PREFIX_TAG` value
- `bloom_fp_error_rate`
- `bloom_entries` - Needs a bit more explanation. Since the bloom filter *can
  not* be resized, it needs to be set to expected number of *distinct* IP addresses
  communicating with specified prefix for the desired period of time (this period
  could be the expected aggregation interval on the Aggregator Service or simply
  `-t`). The false-positive rate *will get worse* than specified by `bloom_fp_error_rate` if more
  entries than configured is inserted!
- `api_url` - HTTP endpoint to which the bloom filter is POST-ed at the end of
  each interval (`-t`).

See `example_config.json`.

- JSON keys not used by this module are ignored and will __not rise error__!
- Compatible with `prefix_tags` module configuration


Future development
------------------

- Add `gzip` compression
- Add client/server authentication


[1]: https://en.wikipedia.org/wiki/Bloom_filter
[2]: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=1204223
[3]: https://github.com/jvirkki/libbloom

