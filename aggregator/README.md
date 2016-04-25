## THIS MODULE IS CURRENTLY UNDER DEVELOPMENT

---

---

# Aggregator module - README

## Description
This NEMEA module filters and aggregates input flows by given rules and sends them to output

## Interfaces
- Input: One UniRec interface
  - Template MUST contain fields TIME_FIRST and TIME_LAST
- Output: Any number of interfaces are supported (MAX_OUTPUT_COUNT defined at compilation time)
  - Format: TIME folowed by one field per rule

## Parameters
### Module specific parameters
- `-t NUMBER`        Output period (sec). Record is emitted every given interval (time is driven by flows, not real time). Default: 60 seconds.
- `-d NUMBER`        Output is delayed by given time interval (sec). This value is necessary and should match active timeout at flow gathering (e.g. flow_meter module) plus 30 seconds. Some flows will be missed if value is too small.
- `-I NUMBER`        When incoming flow is older then inactive timeout, all counters are trashed and reinitialized (module soft restart). Default: 900 seconds.
- `-r STRING`        Rule defining one value to be aggregated. Whitespaces are trimmed completely. Syntax: -r "NAME:AGGREGATION_FUNCTION(FIELD)[:FILTER]"
  - NAME ~ /^[A-Za-z][A-Za-z0-9_]*$/
  - AGGREGATION_FUNCTION ~ /^(SUM|COUNT|AVG|RATE|COUNT_UNIQ)$/
  - FIELD ... any field present in input template
  - FILTER ... any kind of filter handled by UR Filter library (like unirecfilter module)

  - e.g. -r "incoming_buddies : COUNT_UNIQ(SRC_IP) : DST_IP >= 192.168.1.0 && DST_IP <= 192.168.1.255"
  - Maximum count of rules per output is defined at compilation time - MAX_RULES_COUNT
- `-R`               Following rules (-r) will be applied to next output interface

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Flow records are just saying START, END and counts of BYTES and PACKETS. It means we get the information when flow ends (or reaches active timeout) and we know nothing about distribution in period between START and END.

We have to buffer flows for Delay period (param -d) and every flow must be equaly distributed in flow period. Size of buffer is defined by Delay period (-t) multiplied by number of rules (-r).

