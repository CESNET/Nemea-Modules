---
# Aggregator module - README

## Description
This module serves for UniRec records aggregation processing. The module can aggregate UniRec records based on user-specified keys, aggregation functions and time interval. The input of this module is a (infinit) sequence of UniRec records. The output of this module is a sequence of aggregated UniRec records according to user settings.

In configuration file user can specify aggregation functions and aggregation keys. Format is specified [below](./README.md#Configuration-file-format).

Module can work with active and passive timeout.

Module receives UniRec and sends UniRec containing the fields which take part in aggregation process. Only one aggregation function per field is possible in time. Fields TIME_FIRST, TIME_LAST and COUNT are always part of output record, except these fields part of the outout record is only fields specified by user, others are discarded. Please notice the field COUNT (count of aggregated records) is always inside output record.

## Interfaces
- Input: One UniRec interface
  - Template MUST contain fields TIME_FIRST and TIME_LAST and all fields defined in configuration file.
- Output: One UniRec interface
  - UniRec record containing all fields which has aggregation function assigned or are part of the aggregation key. TIME_FIRST, TIME_LAST, COUNT fields are always included.
  
## Parameters
### Module specific parameters
- `-a  --active-timeout <number>`          Active timeout in seconds. 
- `-p  --passive-timeout <number>`         Passive timeout in seconds.
- `-c  --config  <string>`                  Path to configuration file.
- `-n  --name <string>`                  Name of configuration section.
- `-e  --eof`                  Terminate aggregator when EOF is received.
- `-s  --size <number>`             Maximal number of record in Flow cache.  ![equation](https://latex.codecogs.com/gif.latex?2^{<number>})

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

### Aggregation key specification
Key is specified as pair of field type and name of unirec field. Optionaly you can specify reverse key of current key when bi-flow aggregation feature is used (described bellow).

**Example:**
```xml
<field>
    <!--Always KEY for key specification. -->
    <type>KEY</type>
    <!--Key is unirec field named SRC_IP. -->
    <name>SRC_IP</name>  
    <!-- Reverse key name of current key is unirec field named DST_IP (optionaly, used only for bi-flow aggregation. -->
    <reverse_name>DST_IP</reverse_name> 
</field>
```

You can specify more fields as the key in the same time or you dont have to specify the key at all (i.e. all records has the same key).

You can use following data types for key specification: **char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, ip address, mac address, time and string**


### Bi-flow aggregation
Bi-flow aggregation feature merge input and output directions of traffic to one output field. If you want use bi-flow aggregation feature you have to specify bi-flow key. 
Bi-flow key is a set of five fields SRC_PORT, DST_PORT, SRC_IP, DST_IP and PROTOCOL. When bi-flow aggregation key is used, you can specify reverse key name. It means name of field in opposite direction. By default reverse name for bi-flow key is following:
```
name: SRC_PORT, reverse_name DST_PORT
name: DST_PORT, reverse_name SRC_PORT
name: SRC_IP, reverse_name DST_IP
name: DST_IP, reverse_name SRC_IP
```

If you want use bi-flow aggregation feature in aggregation function, you **have to** specify name of reverse field. `<name>` and `<reverse_name>` must have same data type. 
Example:
```xml
<field>
    <!-- Use SUM as aggregation function. -->
    <type>SUM</type>
    <!--Sumarize unirec field named PACKETS in first direction. -->
    <name>PACKETS</name>  
    <!-- Sumarize field PACKETS_REV in opposite direction. -->
    <reverse_name>PACKETS_REV</reverse_name> 
</field>
```
Algorithm stores data for both fields \<name> and <reverse_name>. Decision what field for what direction should be used is made by record with oldest TIME_FIRST timestamp. Oldest record and any other records in the same direction use \<name> as field to aggregation and opposite direction use <reverse_name> field. In postprocessing phase are these fields merged and aggregated.

### Aggregation functions
- **SUM**
Makes total sum of field values. 
    ```xml
    <field>
        <type>SUM</type>
        <name>BYTES</name>   <!--Sumarize unirec field named BYTES. -->
    </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double

- **AVG**
Makes average of field values. Every record stores its sum and in postprocessing phase before the record is sent, the average is computed.
    ```xml
        <field>
            <type>AVG</type>
            <!--Makes avarage of unirec field named BYTES. -->
            <name>BYTES</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double

- **MIN**
Keep minimal value of field across all received records.
    ```xml
        <field>
            <type>MIN</type>
            <!--Minamal value of unirec field named BYTES. -->
            <name>BYTES</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, ip address, mac address, time

- **MAX**
Keep maximal value of field across all received records.
    ```xml
        <field>
            <type>MAX</type>
            <!--Maximal value of unirec field named BYTES. -->
            <name>BYTES</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, ip address, mac address, time

- **FIRST**
Keep the first obtained value of field.
    ```xml
        <field>
            <type>FIRST</type>
            <!--First seen value of unirec field named BYTES. -->
            <name>BYTES</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, ip address, mac address, time, string

- **FIRST_NON_EMPTY**
Keep the first non-empty (zero number or empty string) obtained value of field.
    ```xml
        <field>
            <type>FIRST_NON_EMPTY</type>
            <!--First seen non-empty value of unirec field named BYTES. -->
            <name>BYTES</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, ip address, mac address, time, string

- **LAST**
Keep the last obtained value of field.
    ```xml
        <field>
            <type>LAST</type>
            <!--Last seen value of unirec field named BYTES. -->
            <name>BYTES</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, ip address, mac address, time, string

- **LAST_NON_EMPTY**
Keep the last non-empty (zero number or empty string) obtained value of field.
    ```xml
        <field>
            <type>LAST_NON_EMPTY</type>
            <!--Last seen non-empty value of unirec field named BYTES. -->
            <name>BYTES</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, ip address, mac address, time, string

- **BITAND**
Makes bitwise AND of field with every new received record.
    ```xml
        <field>
            <type>BITAND</type>
            <!--Bit AND the value of unirec field named TCP_FLAGS. -->
            <name>TCP_FLAGS</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64

- **BITOR**
Makes bitwise OR of field with every new received record.
    ```xml
        <field>
            <type>BITOR</type>
            <!--Bit OR the value of unirec field named TCP_FLAGS. -->
            <name>TCP_FLAGS</name>   
        </field>
    ```
    **Data types:** char, int8, uint8, int16, uint16, int32, uint32, int64, uint64

- **APPEND**
Makes array with maximal size of `X` elements. Field of every record is appended to array until the array is full.  
    ```xml
        <field>
            <type>APPEND</type>
            <!-- Append values of unirec field array named PPI_PKT_LENGTHS. -->
            <name>PPI_PKT_LENGTHS</name> 
            <!-- Maximal number of elements of given type send to output. -->
            <size>100</size>
            <!-- Delimiter is used only for fields with string data type. It is one char value. By defalut ';'. -->
            <delimiter>;</delimiter>
        </field>
    ```
    **Data types:** a_int8, a_uint8, a_int16, a_uint16, a_int32, a_uint32, a_int64, a_uint64, a_float, a_double, a_mac, a_time, a_ip address, string
    
    *** (`a_X` means array of X)

- **SORTED_MERGE**
Makes array with maximal size of `X` elements sorted by array of keys. Every records stores its field value and key field value and in postprocessing phase data are sorted by key in specified order and first `X` elements are send to output.
    ```xml
        <field>
            <type>SORTED_MERGE</type>
            <!-- Use values of unirec field array named PPI_PKT_LENGTHS to sorted merge. -->
            <name>PPI_PKT_LENGTHS</name> 
            <!-- Use values of unirec field array named PPI_PKT_TIMES as key to sorted merge. -->
            <sort_key>PPI_PKT_TIMES</sort_key>
             <!-- Sorted data in following order (ASCENDING|DESCENDING). -->
            <sort_type>DESCENDING</sort_type>
            <!-- Maximal number of elements of given type send to output. -->
            <size>100</size>
        </field>
    ```
    **Data types:** a_int8, a_uint8, a_int16, a_uint16, a_int32, a_uint32, a_int64, a_uint64, a_float, a_double, a_mac, a_time, a_ip address, string
    **Data types of the key :** a_int8, a_uint8, a_int16, a_uint16, a_int32, a_uint32, a_int64, a_uint64, a_float, a_double, a_time, a_ip address


### Configuration file format
```xml
<aggregator>
    <!--Unique name of configuration section. More sections is possible in one configuration file. -->
    <id name="section_name"> 
        <field>
            <name>SRC_IP</name>                     
            <type>KEY</type>                        
        </field>
        <field>
            <name>PACKETS</name>
            <type>SUM</type>
        </field>
        <field>
            <name>PPI_PKT_LENGTHS</name>        
            <type>SORTED_MERGE</type>
            <sort_key>PPI_PKT_TIMES</sort_key>   
            <sort_type>DESCENDING</sort_type>    
            <size>200</size>                    
        </field>
    </id>
    <id name="other_section_name"> 
        <field>
            <name>SRC_MAC</name>
            <type>KEY</type>
        </field>
        <field>
            <name>PPI_PKT_LENGTHS</name>        
            <type>APPEND</type>
            <size>100</size>                    
        </field>
    </id>
</aggregator>
```
### Example
``
$ ./biflow_aggregator -i u:input,u:output -c path/to/config.xml -n section_name -a 40 -p 10 -s 20
``
