# luamodule
This NEMEA module receives records from one interface and send them to another.
Received fields can be manipulated (get/set field, add/del fields) using input script in LUA language.

## Requirements
To compile this module, you will need the following packages:
- `lua-devel`
- `lua-libs`

## Arguments
- `-i STRING`  TRAP interface specifier.
- `-l STRING`  Path to LUA script.
- `-n`         Don't forward EOF message.

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
- `ur_id`   - Gets ID of specified unirec field.
- `ur_ip`   - Constructs IP address object (string capable of using mask operator '/')
- `ur_ip4`  - Check if IP address object is of version 4.
- `ur_ip6`  - Check if IP address object is of version 6.
- `ur_drop` - Drop unirec message currently being processed.

Module has one input and one output interface. Input template and record can be read only and output template and record are write only.

Record number is saved in `_REC_COUNT` global variable.

`on_init` function may contain calls of the following functions:
- `ur_type`
- `ur_id`
- `ur_ip`
- `ur_ip4`
- `ur_ip6`

`on_template_recv` function may contain calls of the following functions:
- `ur_add`
- `ur_del`
- `ur_type`
- `ur_id`
- `ur_ip`
- `ur_ip4`
- `ur_ip6`

`on_record_recv` function may contain calls of the following functions:
- `ur_get`
- `ur_set`
- `ur_type`
- `ur_id`
- `ur_ip`
- `ur_ip4`
- `ur_ip6`
- `ur_drop`


### ur\_get
Arguments and return values:
- `ur_get()`                     - Return table with all fields with field name as key and value as unirec field specific value.
- `ur_get(name1[,name2, ...])`   - Return unirec field specific value for each argument or nil if field does not exists. Accept string arguments or number (ID).

Example:
```
local bytes, packets = ur_get("BYTES", "PACKETS")
local allfields = ur_get()
for key, val in pairs(allfields) do
   print(key, val)
end
```

### ur\_set
Arguments and return values:
- `ur_set(name1, value1[,name2, value2, ...])`  - Return true if field was set, false otherwise. Accept unirec field string name or ID and unirec specific value.

Example:
```
-- template: "int32* FOO, uint32 BAR, ipaddr IP"
local ret1, ret2, ret3 = ur_set("FOO", {1,2,3,4,5}, "BAR", 12345, "IP", ur_ip("10.200.4.1"))
```

### ur\_add
Arguments and return values:
- `ur_add(fields1 [, fields2, ...])`   - Return true if change of template succeded, false otherwise. Accept strings with field name and type definition.

Example:
```
ur_add("int32 MY_FIELD1")
ur_add("int32 MY_FIELD2", "ipaddr FOO, uint8* BAR_ARR")
```

### ur\_del
Arguments and return values:
- `ur_del()`                           - Delete all fields from template. Does not have return value.
- `ur_del(fields1 [, fields2, ...])`   - Return true for each argument if field was found and removed, false otherwise. Accept unirec field name string or ID.

Example:
```
local ret1, ret2, ret3, ret4 = ur_del("SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT")
local ret_tab = table.pack(ur_del("PROTOCOL", "DIR_BIT_FIELD"))
```

### ur\_type
Arguments and return values:
- `ur_type()`                          - Return table with field name, field type pairs for all fields in output template.
- `ur_type(fields1 [, fields2, ...])`  - Return string with type of field for each argument, nil if field does not exists. Accepts strings with unirec field name.

Example:
```
-- template: "int32* FOO, uint32 BAR, ipaddr IP"
print(ur_type("FOO", "BAR", "ABC"))
-- "int32*" "uint32" nil
```

### ur\_id
Arguments and return values:
- `ur_id(field1 [, field2, ...])`  - Return number with ID of field for each argument, nil if field does not exists. Accepts strings with unirec field name.

Example:
```
-- template: "int32* FOO, uint32 BAR, ipaddr IP"
print(ur_id("FOO", "BAR", "ABC"))
-- 0 2 nil
```

### ur\_ip
Arguments and return values:
- `ur_ip(ip1 [, ip2, ...])`   - Return IP address object for each IP string argument, nil when address parsing failed. Accepts strings with IP v4 or v6 addresses.

IP address can be masked using `/` operator. Comparsion should be done with strings e.g. `tostring(ip1) == tostring(ip2) or tostring(ip) == "10.0.0.1"`  Example:
```
local ip1, ip2 = ur_ip("192.168.5.200", "::1")
print(ip1 / 24, ip2) -- mask 192.168.5.200 with /24
-- prints 192.168.5.0 ::1
```

### ur\_ip4
Arguments and return values:
- `ur_ip4(ip1 [, ip2, ...])`   - Return true for each argument if address is IPv4, false otherwise. Accept IP address strings and objects.

### ur\_ip6
Arguments and return values:
- `ur_ip6(ip1 [, ip2, ...])`   - Return true for each argument if address is IPv6, false otherwise. Accept IP address strings and objects.

### ur\_drop
Arguments and return values:
-  `ur_drop()`    - Drop unirec message currently being processed.
