# Backscatter module - README

## Description
Extract features from backscatter like traffic. (Oneway flow communication with flags typical for backscatter packets)

## Interfaces
- Inputs: 1 (Flow data source)
- Outputs: 1 (Extracted features from backscatter like traffic)

## Parameters
-  `-a  --active ACTIVE`           Active timeout in seconds. (Default 7200)
-  `-p  --passive PASSIVE`          Passive timeout in seconds. (Default 150)
-  `-t  --threshold THRESHOLD`       Export threshold, feature vector must contain at least stated number of flows to be exported. (Default 30)
-  `-r  --c_rate C_RATE`           Expected rate of incoming records in flows per second (to estimate Bloom history size). (Default 400 000)
-  `-s  --c_history_size C_HISTORY_SIZE`   Size of connection history in seconds. (Default 120)
-  `-f  --c_history_fp C_HISTORY_FP`      False positive rate for connection history (Bloom filter). (Default 0.05)
-  `-R  --f_rate F_RATE`          Expected rate of backscatter like flows per second. (Default 10 000)
-  `-S  --f_history_size F_HISTORY_SIZE`  Size of feature history in seconds. (Default 1800)
-  `-F  --f_history_fp F_HISTORY_FP`      False positive rate for feature history (Bloom filter). (Default 0.01) 
-  `-w  --window L_WINDOW`           Left (past) time window for incoming flows in seconds (flows outside of this window are ignored). (Default 60)
-  `-W  --Window R_WINDOW`           Right (future) time window for incoming flows in seconds (flows outside of this window are ignored). (Default 30)
-  `-o  --out OUT`              Periodically flush backscatter buffer after OUT number of flows. Default value is zero (no forced flushes). This parameter is used only for test purposes to simulate outages. (Default 0 - do not flush)
- `-P  --print`                     Print chosen parameters and performance statistics. (Not default)

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Algortihm filters oneway traffic with the help of Bloom filter (flows corresponding to bidirectionial communication are removed in this step). Oneway traffic with backscatter like flags (TCP) or type/code (ICMP) is than aggregated based on source IP address (potential victim of DDoS). Aggregated data for each potential victim are represented in a form of feature vector which is than sent to output interface. Only feature vectors consisting of atleast THRESHOLD flows are sent to output interface. Classificaiton of feature vector into DDoS class may be done with the use of *backscatter_classiifer* detection module. This  module (*backscatter*) is only used for flow traffic filtering and feature extraction from backscatter like traffic.

Aggregation to feature vector is similar to packet to flow aggregation (NetFlow) and is determined by passive/active timeouts. Key of aggregation is victim IP address. 

## Notes
All specific paremeters were experimentally determined and usage of default parameters is recommended.  Therefore to run the module only input and output interface needs to be specified.

## Examples

./backscatter -i "u:flow_data_source,u:backscatter"



