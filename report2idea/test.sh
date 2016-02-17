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
# IMPORTANT INFORMATION ABOUT THIS SCRIPT:
#
# This test script is used to track change of functionality during the development.
# It expects human check of output at the first time.
# Later on, it is possible to compare result of reporter according to previously checked.
# Note: it is necessary to remove all variable items such as UUID and timestamps,
# since it is not possible to compare them using this simple script.
#
#
# How to create input and output?
# INPUT:
# use logger with file interface to store data:
#   ../../public-modules/logger/logger -t -i f:vportscan.trapcap
#
# write data into script (base64 coded):
#   echo "vp=\"$(base64 vportscan.trapcap)\"" >> test.sh
#
# OUTPUT:
# store output from reporter and clean it from variable info:
#   ./vportscan2idea.py -i u:vportscan.trapcap --file /dev/stdout -n vportscan |
#   sed 's/"[^"]*Time": "[^"]*"//g; s/"ID": "[^"]*"//g' > vp-out 
# compress, base64 code the result and write it into the script:
#   echo "vsout=\"$(gzip < vp-out|base64)\"" >> test.sh
#
#


# input data:
hs="AgAAAJkAAABpcGFkZHIgRFNUX0lQLGlwYWRkciBTUkNfSVAsdGltZSBUSU1FX0ZJUlNULHRpbWUg
VElNRV9MQVNULHVpbnQzMiBFVkVOVF9TQ0FMRSx1aW50MTYgRFNUX1BPUlQsdWludDE2IFNSQ19Q
T1JULHVpbnQ4IEVWRU5UX1RZUEUsdWludDggUFJPVE9DT0wsc3RyaW5nIE5PVEVBAwAAUQAAAAAA
AAAAAAAAAAD/////AAAAAAAAAAALFgwW/////wAAAAB0q7tWAAAAAC+su1bzAAAAAAAAAAIGAAAT
AGhvcml6b250YWwgU1lOIHNjYW5RAAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAxJDBz/////AAAA
ABysu1YAAAAAIKy7VjQCAAAAAAAAAgYAABMAaG9yaXpvbnRhbCBTWU4gc2NhblEAAAAAAAAAAAAA
AAAA/////wAAAAAAAAAADQ4RL/////8AAAAADKy7VgAAAAAZrLtW7QAAAAAAAAACBgAAEwBob3Jp
em9udGFsIFNZTiBzY2FuUQAAAAAAAAAAAAAAAAD/////AAAAAAAAAAALFgwP/////wAAAAAHq7tW
AAAAADusu1Z1AQAAAAAAAAIGAAATAGhvcml6b250YWwgU1lOIHNjYW5RAAAAAAAAAAAAAAAAAP//
//8AAAAAAAAAAFgbEBv/////AAAAAAOsu1YAAAAAGay7Vu4AAAAAAAAAAgYAABMAaG9yaXpvbnRh
bCBTWU4gc2NhblEAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAVzxTD/////8AAAAAAKy7VgAAAAAZ
rLtW5wAAAAAAAAACBgAAEwBob3Jpem9udGFsIFNZTiBzY2FuUQAAAAAAAAAAAAAAAAD/////AAAA
AAAAAAAWExEL/////wAAAAAQq7tWAAAAADusu1YfAwAAAAAAAAIGAAATAGhvcml6b250YWwgU1lO
IHNjYW5RAAAAAAAAAAAAAAAAAP////8AAAAAAAAAAEsKERj/////AAAAAAusu1YAAAAAGay7VvgA
AAAAAAAAAgYAABMAaG9yaXpvbnRhbCBTWU4gc2NhblEAAAAAAAAAAAAAAAAA/////wAAAAAAAAAA
CgoSFP////8AAAAADKy7VgAAAAAZrLtW6gAAAAAAAAACBgAAEwBob3Jpem9udGFsIFNZTiBzY2Fu
UQAAAAAAAAAAAAAAAAD/////AAAAAAAAAAAPFEEL/////wAAAAAErLtWAAAAABmsu1b4AAAAAAAA
AAIGAAATAGhvcml6b250YWwgU1lOIHNjYW4BAAA="

vp="AgAAAIoAAABpcGFkZHIgRFNUX0lQLGlwYWRkciBTUkNfSVAsdGltZSBUSU1FX0ZJUlNULHRpbWUg
VElNRV9MQVNULHVpbnQzMiBQT1JUX0NOVCx1aW50MTYgRFNUX1BPUlQsdWludDE2IFNSQ19QT1JU
LHVpbnQ4IEVWRU5UX1RZUEUsdWludDggUFJPVE9DT0xbAgAAOgAAAAAAAAAAAAQCBRX/////AAAA
AAAAAAAvBRVS/////8L1KDwsirtWGARWbqSNu1aWAAAA6hO7JgEGOgAAAAAAAAAAAAEICSf/////
AAAAAAAAAABYBREX/////wAAAAAki7tWJAaBVa2Nu1aQAQAACJO3twEGOgAAAAAAAAAAAAEICSf/
////AAAAAAAAAABiBDBV/////yCwcug1i7tWoUW2UwaNu1aQAQAAN5qokQEGOgAAAAAAAAAAAAEI
CSf/////AAAAAAAAAABFBxIb/////90kBuFqi7tWkxgEVtaNu1Y0CAAAK2AszQEGOgAAAAAAAAAA
AAEICSj/////AAAAAAAAAABFBxIb/////2ZmZuZxi7tW4XoU7tmNu1Y0CAAATmAszQEGOgAAAAAA
AAAAAAEICSf/////AAAAAAAAAABiBDBS/////65H4VpTi7tWZDvfb9GNu1YgAwAAjgzA0QEGOgAA
AAAAAAAAAAEICSf/////AAAAAAAAAABiBDBW/////yuHFjlGi7tWObTItp6Nu1YmAgAAL9iokQEG
OgAAAAAAAAAAAAEICSf/////AAAAAAAAAAAtAk5a/////9v5fspGi7tWm8QgkMKNu1aKAgAAomBp
cQEGOgAAAAAAAAAAAAEICSf/////AAAAAAAAAABiBDBU/////2ZmZkZUi7tWSQwCa5+Nu1b0AQAA
SWOokQEGOgAAAAAAAAAAAAEICSf/////AAAAAAAAAABJCQ4+/////1G4HkVJi7tWLbKdz7mNu1bC
AQAA2NNIUAEGAQAA"

# output data:
hsout="H4sIAKfBu1YAA9WVwWrDMAyG73uKoPMobZIt7W6jXWkvoSyDHUYPxjOdIbGCrTK60nefpe6yJ7BL
Lo5+Rb/8IZHzfQEtfhp4Kj7O8HYa5QTrHr8hSh0psoGsVj3s+f1d5NYMRrG+wUCcE64RTmnVwDXg
K0qBJbjEcBRWJmhvR7LoWN+gtz/oSPXFiJ6KoJXjkkt0bolHRzGprCv5dI1+UByA7erleSppiswB
/Un6eTUa3aSLFZx1B7j6dXj0+u9i210tidOJPNLoziOhREmPsOcu5d7/zC9356wJPTzW6QiJee6E
yqpJOENsnjuhqkm4ZWKeO6GymqecofktEJqlJDTLn1CzWKQjJOa5EyrrlFtW38SWJfzbi3n2hDKY
oV+UmwscVAsAAA=="

vsout="H4sIAJjBu1YAA+2W32vCMBDH3/dXlDzLkdS0TX2TOsEXkVUmY8gINZSCJiWNGyL+70vi2EBQGCOw
jT7mLt/78eG45IgKbkSt9AGNomf0IColoay4lI2s0XoQobnaCOc7onFd61Uj7QFhPCJ4hDGyF5aH
1l9A0616c4bScNN0pqn41kcoV949FzvBnf+1Vdp0NsfLRhhRGaXPifjOxflyo5M1uwRc18Kca5gt
qA9GIYYEYuKVC62M8mZTtWh98knVXlfiQpR5DbD4msznm4iu0k1rGuV7fRTa9xK5mqJ9Z8FEy2IR
lU9z102hpCzUXroCSYKtZar0jrsjmk3ux47RIDrdHf8oaYsLchjm3yLNmCVNMoiHgUhT3JP23pwB
BcqAJT3psKTTHDIgDOIsEOmY/FvUFPeof+dUf+6PUG8i60lfkE4DkU7638fHP8/+8iCzwqtb54ek
0570xUzTUDPdb4+zKBtaDaGQhtrT9MZMvwN+rnx8Jg4AAA=="

# The Test:
data=$(mktemp)
errors=0

# TEST OF HOSTSTATS2IDEA
# prepare stored input
echo -n "$hs" | base64 -d > "$data"
# generate output
./hoststats2idea.py -i "f:$data" -n hoststats --file /dev/stdout |
   # clean it from variable info
   sed 's/"[^"]*Time": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$hsout" | base64 -d | gunzip) ||
   # on error, print it and remember it
   { echo "hoststats2idea FAILED :-("; ((errors++)); }

# TEST OF VPORTSCAN2IDEA
# prepare stored input
echo -n "$vp" | base64 -d > "$data"
# generate output
./vportscan2idea.py -i "f:$data" -n vportscan --file /dev/stdout |
   # clean it from variable info
   sed 's/"[^"]*Time": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$vsout" | base64 -d | gunzip) ||
   { echo "vportscan2idea FAILED :-("; ((errors++)); }

# cleanup
rm "$data"

# exit with right status
if [ "$errors" -gt 0 ]; then
   exit 1
else
   exit 0
fi

