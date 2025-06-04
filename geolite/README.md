# Geolite

## Module description

This module outputs flow records with geolocation data using a [geolite database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).


## Input data

This module expects flow records in Unirec format. The required fields
are determined by run time parameters.


## Output data

Flows are sent on the output interface, also in Unirec format, they
contain geolocation data. The fields included in the output interface will vary depending on the selected database type. 

Below are the fields that will be set for each database type:
* `country` 
  * ipaddr `ip`
  * string `name`
  * string `iso_code`
  * uint32 `geoname_id`
  * uint32 `is_in_european_union`

* `city`
  * ipaddr `ip`
  * string `country_name`
  * string `country_iso_code`
  * uint32 `country_geoname_id`
  * uint32 `is_in_european_union`
  * string `city_name` 
  * float  `latitude`
  * float  `longitude`
  * uint32 `accuracy_radius`

* `asn`
  * ipaddr `ip`
  * uint32 `asn`
  * string `string autonomous_system_organization`


## Module parameters

In addition to the implicit *libtrap* parameters `-i IFC_SPEC`, `-h`
and `-v` (see [Execute a
module](https://github.com/CESNET/Nemea#try-out-nemea-modules)) this
module takes the following parameters:

* `-d` `--db` path
  
  * Specify path to the database file.

* `-f` `--fields` field1,field2,... 

  * Specify the name of field(s) from the input interface, which will be used for geolocation and lookup in the database (case sensitive).
  If multiple fields are specified, they must be separated by a comma.

* `-t` `--type` {country, city, asn}
  
  * Specify the type of GeoLite database. The default value is `country`.

* `-c` `--cache` number

  * Specify the number of lookup calls that will be cached. Set to `0` to disable caching. The default value is `128`.


## Example
The following command :

`./geolite.py -i f:/etc/nemea/data/data.dan.trapcap,f:test.trapcap -d '/usr/share/GeoIP/GeoLite2-Country.mmdb' -t country -f "SRC_IP,DST_IP"`

will be interpreted as follows:

* `-i f:/etc/nemea/data/data.dan.trapcap,f:test.trapcap`
  sets the input and output interfaces to a file.

* `-d '/usr/share/GeoIP/GeoLite2-Country.mmdb'` sets the path to the database file.

* `-t country` sets the database type to `country` (can be omitted as it is the default).

* `-f "SRC_IP,DST_IP"` specifies the names of the fields containing IP addresses to be used for geolocation.

<!--- Local variables: -->
<!--- mode: markdown; -->
<!--- mode: auto-fill; -->
<!--- mode: flyspell; -->
<!--- ispell-local-dictionary: "british"; -->
<!--- End: -->
