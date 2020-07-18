#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test vpndetector "$pcap_dir/vpndetector-sample.pcap"

