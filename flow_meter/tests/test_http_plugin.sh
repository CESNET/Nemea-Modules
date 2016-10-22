#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

test_plugin http "$pcap_dir/http-sample.pcap"

