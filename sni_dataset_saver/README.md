# TLS SNI dataset saver

## Interfaces
- Inputs: 1 (Flow data source)
- Outputs: 2 (SNI output, stats output)

# Example of domains file

**DOMAINS.csv** format:

- `Id,Tag,Merged Domains`
- `0,zoom,"*.zoom.us, *.zoomgov.com"`
- `1,webex,"*.ciscospark.com, *.wbx2.com, *.webex.com"`


./sni_dataset_saver -f domains.csv -t 300 -i u:input,u:output,u:stats