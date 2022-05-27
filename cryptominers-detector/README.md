# Cryptominers Detector
Cryptominers detection software consits of two NEMEA modules - detector and aggregator - and Python script used for IDEA reporting.

Before thes first run, Cython modules need to be compiled:
```
./configure.sh
```

Detector takes as an input flows from exporter and sends to its output flows marked as a miner.
Aggregator takes as an input flows from detector and sends raw alerts to its output.
IDEA reporter takes raw alerts from aggregator on its input and sends alerts to Warden system.

Detector and aggregator have several customizable options, available via `-h` argument.

## Example usage
```
# Detector with buffer size 100 000, DST threshold 0.42 and ML threshold 99.60% 
./minerdetector.py -b 100000 -d 0.42 -t 0.996 -i u:flows_in,u:miner_flows

# Aggregator with active timeout 10 flows and passive timeout 15 minuts
# Connected to the output of detector
./mineraggregator.py -a 10 -p 15 -i u:miners_flow,u:raw_miners_alerts
```