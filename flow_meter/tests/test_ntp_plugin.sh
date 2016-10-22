#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

test_plugin ntp "$pcap_dir/ntp-sample.pcap"

