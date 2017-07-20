# Link_traffic module - README

## Description
link_traffic processes flow data (sums flows, bytes, packets for each LINK_BIT_FIELD). Munin plugin then connects to it via UNIX socket to create graphs.

Module is configured by sysrepo. Data model is in 'link_traffic.yang' and basic configuration in 'link_traffic.data.xml'. More about sysrepo configuration below.

## Interfaces
- Input: 1
- Output: 0

## Module configuration
This module is configured by sysrepo. You load yang module to your sysrepo datastore by:
```
sudo sysrepoctl --install --module=link-traffic --yang=link_traffic.yang --owner=user:user --permission=644
```
To upload initial configuration to startup datastore use:
```
sysrepocfg --datastore=startup --import=link_traffic.data.xml --format=xml link-traffic
```
Then if you want to edit running configuration while the module is running use:
```
sysrepocfg -e vim link-traffic
```
link_traffic will check if you configuration is valid and if it is, it will change the output accordingly.

## Parameters
### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Module collects statistics about flows according to LINK_BIT_FIELD. Running module creates a UNIX socket (/var/run/libtrap/munin_link_traffic). Munin plugin then connects to this socket and gets formatted string with data. The format is the following (the number of headers is not limited):

```
"header1, header2, header3\n
value1, value2, value3"
```
When munin plugin starts it checks /tmp/munin_link_traffic_data.txt. If it is actual enough it uses cached data, if its not actual it connects to UNIX socket and creates new cache file.

## Install Munin script

In order to get data into munin server you need to set it up. Easies way is to execute suggested commands to activate graphs you want: `munin-node-configure --suggest --shell`

When the confituration is done you need to restart munin-node service: `service munin-node restart`
