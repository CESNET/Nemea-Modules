#!/bin/bash
#set -e

die_if_not_running() {
    local pid=$1
    local error_message=$2
    if not kill -0 "$pid" 2>/dev/null; then
        echo $error_message
        exit 1
    fi
}

run_test_with_global_timeout() {
    local input=$1
    local output=$2
    local reference=$3
    local config=$4
    local global_timeout=$5

    (../biflow_aggregator -i "u:lr,u:ba" -e -c config.xml -n $config -g $global_timeout & ) || true
    local AGGREGATOR_PID=$!
    sleep 0.5
    die_if_not_running $AGGREGATOR_PID "Failed to start biflow aggregator"

    ../../logger/logger -w $output -i "u:ba" &  
    local LOGGER_PID=$!
    sleep 0.5
    die_if_not_running $LOGGER_PID "Failed to start logger"

    ../../logreplay/logreplay -f $input -i "u:lr" &  
    local LOGREPLAY_PID=$!
    sleep 0.5
    die_if_not_running $LOGREPLAY_PID "Failed to start logreplay"

    sleep 3
    wait $LOGREPLAY_PID
    kill $AGGREGATOR_PID 2>/dev/null
    sleep 0.2
    kill $LOGGER_PID 2>/dev/null
    wait $LOGGER_PID
    
    if ! colordiff $output $reference; then
        echo $output doesnt match $reference
        success="false"
    fi
}

script_path="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd $script_path
success="true"
mkdir -p outputs 
for input in inputs/input*; do
    basename=$(basename "$input")
    echo Found $basename
    if [[ $basename =~ input([0-9]+)_(.+) ]]; then
        index="${BASH_REMATCH[1]}"
        config="${BASH_REMATCH[2]}"
        output=outputs/output$index
        reference=references/reference$index
    else    
        echo $input
        echo "Incorrect input name. Must be input<index>_<config_name>"
        exit 1
    fi

    echo "Running test without global timeout..."
    run_test_with_global_timeout $input ${output}_gt0 ${reference}_gt0 $config "0"

    echo "Running test with relative global timeout..."
    run_test_with_global_timeout $input ${output}_gt5r ${reference}_gt5r $config "5r"

    echo "Running test with absolute global timeout..."
    run_test_with_global_timeout $input ${output}_gt5a ${reference}_gt5a $config "5a"

done

if [ "$success" = "true" ]; then
    echo "All tests passed successfully."
else
    echo "Some tests failed."
    exit 1
fi