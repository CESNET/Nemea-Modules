#!/bin/bash

prog1=nf
prog2=nfdump
test_file="/mnt/data/aconetnfcapd.201211181035"
out_file="measurement.$$"


#rm -rf ${out_file}

echo "Testing ${prog1}..." >> ${out_file}
for ((i=0;i<10;i++))
do
	./${prog1} -i "b;" ${test_file} >> ${out_file}
done

echo "Testing ${prog2}..." >> ${out_file}
for ((i=0;i<10;i++))
do
	./${prog2} -i "b;" ${test_file} >> ${out_file}
done
