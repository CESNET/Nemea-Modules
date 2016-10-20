#!/bin/sh

. ./test_plugin.sh

test_plugin http "$pcap_dir/http-sample.pcap"

