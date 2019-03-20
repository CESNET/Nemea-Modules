#!/bin/bash
#
# COPYRIGHT AND PERMISSION NOTICE
# 
# Copyright (C) 2016 CESNET, z.s.p.o.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the distribution.
#   3. Neither the name of the Company nor the names of its contributors may
#      be used to endorse or promote products derived from this software
#      without specific prior written permission.
# 
# ALTERNATIVELY, provided that this notice is retained in full, this product
# may be distributed under the terms of the GNU General Public License (GPL)
# version 2 or later, in which case the provisions of the GPL apply INSTEAD OF
# those given above.
# 
# This software is provided "as is", and any express or implied warranties,
# including, but not limited to, the implied warranties of merchantability
# and fitness for a particular purpose are disclaimed. In no event shall the
# company or contributors be liable for any direct, indirect, incidental,
# special, exemplary, or consequential damages (including, but not limited to,
# procurement of substitute goods or services; loss of use, data, or profits;
# or business interruption) however caused and on any theory of liability,
# whether in contract, strict liability, or tort (including negligence or
# otherwise) arising in any way out of the use of this software, even if
# advised of the possibility of such damage.
#
# ===========================================================================
#
#
# IMPORTANT INFORMATION ABOUT SCRIPTS:
#
# Test scripts are used to track change of functionality during the development.
# It expects human check of output at the first time.
# Later on, it is possible to compare result of reporter according to previously checked.
# Note: it is necessary to remove all variable items such as UUID and timestamps,
# since it is not possible to compare them using this simple script.
#
#
# How to create test script?
#
# test script for vportscan will be created as an example
#
# cd into your directory and create test script
#    cd vportscan
#    echo "#!/bin/bash" >test.sh
#
# How to create input and output?
# INPUT:
#  create trapcap file
#    ../../../detectors/vportscan_detector/vportscan_detector -i u:input,f:vportscan.trapcap
#
# write data into script (compressed and base64 coded):
#    echo "in='$(gzip <vportscan.trapcap | base64)'" >> test.sh
#
# OUTPUT:
# store output from reporter and clean it from variable info:
#    ./vportscan2idea.py -i f:vportscan.trapcap --file /dev/stdout -n vportscan |
#    sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' >vp-out
#
# compress, base64 code the result and write it into the script:
#    echo "out='$(gzip < vp-out | base64)'" >> test.sh
#
# TEST:
# add these two lines into the script:
#    . ../test.sh
#    test_conversion "vportscan" "vportscan" "$in" "$out"
#
# the first argument for test_conversion function is the script name and second is node name,
# which you specified when creating output data (-n parameter)
# do not forget to add test to the Makefile.am
#

# usage: json_cleanup reads from stdin and writes modified data into stdout
# It removes keys from JSON that change and sorts the remaining ones alphabetically.
# The sorting is important because of diff(1) that is used.  (Note: JSON has not fixed
# order of keys)
json_cleanup()
{
    gawk '{
       gsub(/^[^{]*/, "")
       gsub(/'"'"'/, "\"")
       gsub(/,* *"[^"]*Time": *"[^"]*",*/, ",")
       gsub(/,* *"ID": *"[^"]*",*/, ",")
       gsub(/:/, ",")
       gsub(/{/, ",")
       gsub("}", ",")
       gsub("]", ",")
       gsub(/\[/, ",")
       gsub(" ", "")
       n = split($0, fields, ",")
       j=1
       for (i=1; i<=n; i++) {
         arr[j++]=fields[i]
       }
       asort(arr);
       for (i=1; i<length(arr); i++) {
          printf("%s,", arr[i]);
       }
       printf("%s\n", arr[i]);
       delete arr
   }' | tr -s , | sed 's/^[, ]*//;'
}

#usage: test_conversion <script name> <node name> <input data> <output data> <optional params>
test_conversion()
{
   # The Test:
   data=$(mktemp)
   errors=0
   config="
custom_actions:
  - id: file
    file:
      path: /dev/stdout
rules:
- id: 1
  condition: Null
  actions:
  - file"

   if [[ -z "$3" || -z "$4" ]]
   then
      echo "empty input or output data"
      rm "$data"
      exit 1
   fi

   SCRIPT_NAME="$1"
   NODE_NAME="$2"
   INPUT_DATA="$3"
   OUTPUT_DATA="$4"
   shift 4
   # prepare stored input
   echo -n "$INPUT_DATA" | base64 -d | gunzip > "$data"
   # generate output
   "$srcdir/${SCRIPT_NAME}2idea.py" -i "f:$data" -n "$NODE_NAME" --config <(echo "$config") "$@" | tee "$SCRIPT_NAME.idea" |
      # clean it from variable info
      json_cleanup |
      # compare it with prepared expected data (previously base64 encoded and gzipped)
      diff -u - <(echo -n "$OUTPUT_DATA" | base64 -d | gunzip  | json_cleanup)  ||
      { echo "${1}2idea FAILED :-("; ((errors++)); }

   # cleanup
   rm "$data"

   # exit with right status
   if [ "$errors" -gt 0 ]; then
      exit 1
   else
      exit 0
   fi
}

