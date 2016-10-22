#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

test_plugin sip "$pcap_dir/sip-sample.pcap"

