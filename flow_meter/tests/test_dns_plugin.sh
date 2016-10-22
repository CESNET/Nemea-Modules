#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

test_plugin dns "$pcap_dir/dns-sample.pcap"

