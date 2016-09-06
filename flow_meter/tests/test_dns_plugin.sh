#!/bin/sh

. ./test_plugin.sh

test_plugin dns "$pcap_dir/dns-sample.pcap"

