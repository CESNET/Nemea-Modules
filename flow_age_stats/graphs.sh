#!/bin/bash

echo "Press 1 if you want graphs for TIME_FIRST and TIME_LAST. Press 2 if you want graphs for each FLOW_END_REASON:"
read choice

if [ "$choice" = "1" ]; then
    echo "Making graphs for all the flows encountered..."
    gnuplot -c plot.gp "0_time_first.txt" "0_time_last.txt" ""
elif [ "$choice" = "2" ]; then
    echo "Making graphs for each FLOW_END_REASON..."
    gnuplot -c plot.gp "0_time_first.txt" "0_time_last.txt" "0_no_FLOW_END_REASON"
    gnuplot -c plot.gp "1_time_first.txt" "1_time_last.txt" "1_idle_timeout"
    gnuplot -c plot.gp "2_time_first.txt" "2_time_last.txt" "2_active_timeout"
    gnuplot -c plot.gp "3_time_first.txt" "3_time_last.txt" "3_end_of_flow_detected"
    gnuplot -c plot.gp "4_time_first.txt" "4_time_last.txt" "4_forced_end"
    gnuplot -c plot.gp "5_time_first.txt" "5_time_last.txt" "5_lack_of_resources"
else
    echo "Invalid input. Please run the script again and enter either 1 or 2."
    exit 1
fi