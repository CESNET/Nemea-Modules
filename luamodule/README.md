# luamodule
This NEMEA module receives records from one interface and send them to another.
Received fields can be manipulated (get/set field, add/del fields) using input script in LUA language.

## Requirements
To compile this module, you will need the following packages:
- `lua-devel`
- `lua-libs`

## Arguments
- `-i STRING`  TRAP interface specifier.
- `-n`         Don't forward EOF message.
- `-l STRING`  Path to LUA script.

## Architecture
Module expects script to have defined three following functions:
- `on_init`             - Is called when module starts and can contain initialization of global variables.
- `on_template_recv`    - Is called when unirec template changes (new connection is established) and can contain code to add or delete template fields.
- `on_record_recv`      - Is called when new record is received and can contain code to get or set values of fields.

## API functions
Scripts can use the following functions provided by the module:
- `ur_get`  - Gets value of unirec field in input record.
- `ur_set`  - Sets value of unirec field in output record.
- `ur_add`  - Adds new field to output record.
- `ur_del`  - Deletes field from output record.
- `ur_type` - Gets type of unirec field.
- `ur_ip`   - Constructs IP address object (string capable of using mask operator '/')
- `ur_ip4`  - Check if IP address object is of version 4.
- `ur_ip6`  - Check if IP address object is of version 6.

Record number is saved in `_REC_COUNT` global variable.
