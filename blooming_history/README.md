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
some filtering might be necessary (i.e. using `unirecfilter` module). This
module does filter only by configured IP prefix.

See [original whitepaper][2] by which this module is inspired.


Interfaces
----------

- Input: One UniRec interface
  - Template *MUST* contain fields `SRC_IP` and `DST_IP`.


Usage
-----

```
TRAP module, libtrap version: 0.11.4 
===========================================
Name: History gathering module
Inputs: 1
Outputs: 0
Description:
  This module gathers history of communicating entities and stores them in a bloom filter.

Usage:  blooming_history [COMMON]... [OPTIONS]... 

Parameters of module [OPTIONS]:
-------------------------------
  -n  --number <int32>     Expected number of distinct entries (addresess) for long aggregated period.
  -e  --error <float>      False possitive error rate at \"count\" entries.
  -p  --prefix <string>    Protected IP prefix. Only communication with addresses from this prefix will be recorded
  -t  --interval <int32>   Interval in seconds for periodic filter upload to the aggregator service.
  -s  --service <string>   IP address of the aggregator service.


Common TRAP parameters [COMMON]:
--------------------------------
  -h [trap,1]              If no argument, print this message. If \"trap\" or 1 is given, print TRAP help.
  -i IFC_SPEC              Specification of interface types and their parameters, see \"-h trap\" (mandatory parameter).
  -v                       Be verbose.
  -vv                      Be more verbose.
  -vvv                     Be even more verbose.


Environment variables that affects output:
------------------------------------------
  LIBTRAP_OUTPUT_FORMAT    If set to \"json\", information about module is printed in JSON format.
  PAGER                    Show the help output in the set PAGER.
  TRAP_SOCKET_DIR          Change path to socket directory (default: /var/run/libtrap).

```


### Notes

The `-n, --number` needs a bit more explanation. Since the bloom filter *can
not* be resized, it needs to be set to expected number of *distinct* IP addresses
communicating with specified prefix for the desired period of time (this period
could be the expected aggregation interval on the Aggregator Service or simply
`-t`). The false-positive rate *will get worse* than specified by `-e` if more
entries than configured is inserted!


Installation
------------

For this module to be compiled you need:

- `libpthread`
- `libcurl`

This module also uses `libbloom` and includes its slightly modified sources in
`libbloom/` directory. The upstream project can be found on [GitHub][3].


Future development
------------------

- Add `gzip` compression
- Add client/server authentication 


[1]: https://en.wikipedia.org/wiki/Bloom_filter
[2]: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=1204223
[3]: https://github.com/jvirkki/libbloom

