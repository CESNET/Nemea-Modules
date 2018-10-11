#!/bin/bash

# Start aggregator itself and store its PID into variable
/home/slabimic/Nemea/Nemea-Modules/aggregator/agg -i u:input_data,u:aggr_data -k SRC_IP -k DST_IP -s BYTES -s PACKETS -t a:60 & 
PID=$!

# Start logger to pickup aggregated data from unix socket to not to block the interface
/usr/bin/nemea/logger -t -i u:aggr_data >/dev/null &

# Start repeater with source data to send as input to aggregator
/usr/bin/nemea/traffic_repeater -i f:/home/slabimic/Nemea_data/data.trapcap.*,u:input_data

# Send ^C signal to aggregation module and wait to close (complete processing and flush storage)
kill -s 2 $PID

# Wait a bit to gracefully close the aggregation module (when global timeout its good to wait the TIMEOUT_LENGTH + at least second more)
sleep 2;
