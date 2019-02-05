# Resolver

## Module description

This module amends flow records with resolved fields.


## Input data

This module expects flow records in Unirec format. The required fields
are determined by run time parameters.


## Output data

Flows are sent on the output interface, also in Unirec format, they
contain all the fields of the input interface plus the configured
resolved fields from the resolvspec parameter.


## Available resolutions

These resolutions are available:

* dns_ptr: ip address (ipaddr) -> domain name (string)
* dns_a: domain name (string) -> ip address (ipaddr)
* dns_aaaa: domain name (string) -> ip address (ipaddr)
* ent_services: port (uint16)/protocol (uint8) -> service name
  (string)


## Module parameters

In addition to the implicit *libtrap* parameters `-i IFC_SPEC`, `-h`
and `-v` (see [Execute a
module](https://github.com/CESNET/Nemea#try-out-nemea-modules)) this
module takes the following parameters:

* `-u` `--urformat` urformat
  Specify unirec input format.

* `-r` `--resolvspec` infield[/infield] resolution outfield
  Specify field(s), what lookup to do of it/them and where to put the
  result.

For more detailed information see above under [available
resolutions](#available-resolutions).

All fields specified as infields in resolvspec parameters must be
supplied in the urformat parameter for this module to start. Note
though that the downstream module will fail if it requires non
resolved fields you do not specify in the uformat parameter.

<!--- Local variables: -->
<!--- mode: markdown; -->
<!--- mode: auto-fill; -->
<!--- mode: flyspell; -->
<!--- ispell-local-dictionary: "british"; -->
<!--- End: -->
