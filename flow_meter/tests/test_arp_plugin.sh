#!/bin/sh

. ./test_plugin.sh

test_plugin arp "$pcap_dir/arp-sample.pcap"

