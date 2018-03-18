## THIS MODULE IS CURRENTLY UNDER DEVELOPMENT
---

---
# Aggregator module - README

## Description
This module serves for UniRec records aggregation processing. User has to specify parameters for processing including key fields and applied aggregation function. Module can work with 3 different timeout types (Active, Passive, Global) or their combination (Mixed = Active,Passive).

Module receives UniRec and sends UniRec containing the fields which take part in aggregation process. Module use in place aggregation, so only one aggregation function per field is possible. Only fields specified by user are part of output record, others are discarded. Please notice the field COUNT (count of aggregated records) is always inside output record.

## Interfaces
- Input: One UniRec interface
  - Template MUST contain fields TIME_FIRST and TIME_LAST and all fields defined in user input.
- Output: One UniRec interface
  - UniRec record containing all fields which has aggregation function assigned or are part of the aggregation key. TIME_FIRST, TIME_LAST, COUNT fields are always included.
  
## Parameters
### Module specific parameters
- `-k  --key <string>`           Defines received UniRec field name as part of aggregation key.Use individually on each field as -k FIELD_NAME. Module has undefined behaviour when no key specified.
- `-t  --time_window <string>`   Represents type of timeout and #seconds for given type before sending record to output. Use as [G,A,P]:#seconds or M:#Active,#Passive (eg. -t "m:10,25").When not specified the default value (A:10) is used.
- `-s  --sum <string>`           Makes sum of UniRec field values identified by given name.
- `-a  --avg <string>`           Makes average of UniRec field values identified by given name.
- `-m  --min <string>`           Keep minimal value of UniRec field identified by given name.
- `-M  --max <string>`           Keep maximal value of UniRec field identified by given name.
- `-f  --first <string>`         Keep first value of UniRec field identified by given name.
- `-l  --last <string>`          Keep first value of UniRec field identified by given name.
- `-o  --or <string>`            Make bitwise OR of UniRec field identified by given name.
- `-n  --and <string>`           Make bitwise AND of UniRec field identified by given name.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

For more informations and examples visit the http://nemea.liberouter.org/aggregation.
