#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

test_plugin arp "$pcap_dir/arp-sample.pcap"

