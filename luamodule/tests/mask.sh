#!/bin/bash

test -z "${srcdir}" && export srcdir=.

. ${srcdir}/test.sh

run_test "mask.lua" "mixed.ur" "mask.txt"
