# Aggregator module - README

## Description
This NEMEA module filters and aggregates input flows by given rules and sends them to output

## Interfaces
- Input: UniRec flows
- Output interfaces: @TODO undefined yet

## Parameters
### Module specific parameters
- `-t NUMBER`        Output period (sec). Record is emitted every given interval (time is driven by flows, not real time). Default: 60 seconds.
- `-d NUMBER`        Output is delayed by given time interval (sec). This value is necessary and should match active timeout at flow gathering (e.g. flow_meter module) plus 30 seconds. Some flows will be missed if value is too small.
- `-r STRING`        Rule defining one value to be aggregated. Syntax: -r "NAME:AGGREGATION_FUNCTION[:FILTER]"
                       NAME ~ /^[A-Za-z_-]*$/
                       AGGREGATION_FUNCTION ~ /^(SUM|COUNT|AVG|RATE)$/
                       FILTER ... any kind of filter handled by libURFilter

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Flow records are just saying START, END and counts of BYTES and PACKETS. It means we get the information when flow ends (or reaches active timeout) and we know nothing about distribution in period between START and END.

We have to buffer flows for Delay period (param -d) and every flow must be equaly distributed in flow period. Size of buffer is defined by Delay period (-t) multiplied by number of rules (-r).

