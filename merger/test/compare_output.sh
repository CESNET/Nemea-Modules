#!/bin/bash

if [ -z "${builddir}" ]; then
   builddir=.
fi
if [ -z "${srcdir}" ]; then
   srcdir=.
fi

${builddir}/../merger -i f:${srcdir}/in0.trapcap,f:${srcdir}/in1.trapcap,f:out:w

echo Merger finished

diff -u <(${builddir}/../../logger/logger -t -i f:out | sort) ${srcdir}/expected

