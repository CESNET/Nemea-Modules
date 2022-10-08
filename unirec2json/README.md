# Convertor from UniRec to JSON format

This module receives any UniRec format and converts message by message into
JSON format.  The result is sent in form of JSON messages via TRAP output
IFC.

See `./unirec2json.py -h` for help.

## Mappings

Using `-M JSONFILE`, `--maps=JSONFILEA`, it is possible to load a JSON file with
configuration to modify the JSON object after UniRec conversion.

There are three supported operations: `match`, `regex`, `timify`.
Each operation can be listed at most once, however, they can contain
modification of multiple fields (keys) in the JSON.

### match

`match` uses exact match of key `src` to assign the value of `dest`. The value is looked up in `mapping`.

Example:

```
{
  "match": [
    {
      "src": "PROTOCOL",
      "dest": "PROTOCOL_NAME",
      "mapping": {
        "6": "TCP",
        "17": "UDP"
      }
    }
  ]
}
```

This means `PROTOCOL_NAME` is created in the JSON object and its value is set
to "TCP" when `PROTOCOL` is "6", and to "UDP" when `PROTOCOL` is "17".

### regex

`regex` works similarly but it iterates over the listed regular expressions to find the value.

Example:

```
{
  "regex": [
    {
      "src": "PREFIX_NAME",
      "dest": "ISVUT",
      "mapping": {
        "www\\..*": "web",
        "webmail\\..*": "mail"
      }
    }
  ]
}
```

### timify

`timify` coverts values (float, number of seconds) of the listed keys into datetime
```
{
  "timify": [
    "TIME_FIRST",
    "TIME_LAST"
  ]
}
```

