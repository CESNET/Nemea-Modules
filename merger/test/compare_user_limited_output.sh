#!/bin/bash

if [ -z "${builddir}" ]; then
   builddir=.
fi
if [ -z "${srcdir}" ]; then
   srcdir=.
fi

# run merger
time ${builddir}/../merger -i f:${srcdir}/in0.trapcap,f:${srcdir}/in1.trapcap,f:ulout:w -u "ipaddr SRC_IP,ipaddr DST_IP2,uint64 BYTES,uint64 BYTES2,time TIME_FIRST"

# prepare expected data using awk
if [ ! -f expected_user_limited ]; then
  ${builddir}/../../logger/logger -i f:${srcdir}/in0.trapcap |
    awk -F, 'BEGIN {print "ipaddr DST_IP2,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES2,time TIME_FIRST"} {print "::,"$2","$3",0,"$5}'  > expected_user_limited
  ${builddir}/../../logger/logger -i f:${srcdir}/in1.trapcap |
    awk -F, '{print $1",::,0,"$3","$5}'  >> expected_user_limited
  sort < expected_user_limited > expected_user_limited.tmp
  mv expected_user_limited.tmp expected_user_limited
fi

echo Merger finished

diff -u <(${builddir}/../../logger/logger -t -i f:ulout | sort | tee outputsorted ) expected_user_limited
retval=$?

# cleanup
rm -f ulout expected_user_limited

exit $retval

