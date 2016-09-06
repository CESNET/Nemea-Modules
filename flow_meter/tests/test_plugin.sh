#!/bin/bash

flow_meter_bin=../flow_meter
logger_bin=../../logger/logger

pcap_dir=../traffic-samples
ref_dir=test_reference
output_dir=test_output
file_out="$$.data"

# Usage: test_plugin <plugin name> <data file>
function test_plugin() {
   if ! [ -f "$flow_meter_bin" ]; then
      echo "flow_meter not compiled"
      return 1
   fi

   if ! [ -f "$logger_bin" ]; then
      echo "logger not compiled"
      return 1
   fi

   if ! [ -d "$output_dir" ]; then
      mkdir "$output_dir"
   fi

   "$flow_meter_bin" -i f:"$output_dir/$file_out":buffer=off:timeout=WAIT -p "$1" -r "$2" >/dev/null
   "$logger_bin"     -i f:"$output_dir/$file_out" -t | sort > "$output_dir/$1"
   rm "$output_dir/$file_out"

   if diff "$ref_dir/$1" "$output_dir/$1" >/dev/null; then
      echo "$1 plugin test OK"
   else
      echo "$1 plugin test FAILED"
      return 1
   fi
}

