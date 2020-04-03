#!/bin/bash

test -z "${srcdir}" && export srcdir=.

. ${srcdir}/test.sh

run_test "stats.lua" "mixed.ur" "stats.txt"
