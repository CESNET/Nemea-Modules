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

ap="AgAAAMQAAABpcGFkZHIgRFNUX0lQLGlwYWRkciBTUkNfSVAsdWludDY0IFJFUV9CWVRFUyx1aW50
NjQgUlNQX0JZVEVTLHRpbWUgVElNRV9GSVJTVCx0aW1lIFRJTUVfTEFTVCx1aW50MzIgRVZFTlRf
SUQsdWludDMyIFJFUV9GTE9XUyx1aW50MzIgUkVRX1BBQ0tFVFMsdWludDMyIFJTUF9GTE9XUyx1
aW50MzIgUlNQX1BBQ0tFVFMsdWludDE2IFNSQ19QT1JUywMAAFYAAAAAAAAAAAAr5wZ7/////wAA
AAAAAAAAw3FS9v////+OSAEAAAAAAKQ/OwAAAAAAxks3CbHeLVYv3STGO+ItVgEAAAAOBQAADgUA
AKUDAADuCgAANQBWAAAAAAAAAAAAebgu/f////8AAAAAAAAAAMNxUvb/////3wsBAAAAAACkrTkA
AAAAAE+Nl+683i1W2c73U0HiLVYCAAAAHwQAAB8EAACMAwAApAoAADUAVgAAAAAAAAAAAK8rc///
////AAAAAAAAAADDcVL2/////45MAgAAAAAAMTd7AAAAAABuEoPAtt4tVsDKoaVD4i1WAwAAAA4J
AAAOCQAAlAcAALsWAAA1AFYAAAAAAAAAAACt/hwR/////wAAAAAAAAAAk+UBU//////lLQIAAAAA
AI77cAAAAAAAxks36b7eLVYSg8BqROItVgQAAADbCAAA2wgAACIHAABmFQAANQBWAAAAAAAAAAAA
PbIwE/////8AAAAAAAAAAMNxUvb/////mRoBAAAAAAArmkAAAAAAAFg5tGi/3i1W+6nxkkTiLVYF
AAAAWQQAAFkEAAD5AwAA6wsAADUAVgAAAAAAAAAAAHLXetr/////AAAAAAAAAADDcVL2/////1ze
AQAAAAAAXQthAAAAAACd76cmwt4tVlpkOx9H4i1WBgAAAFwHAABcBwAA+AUAAOcRAAA1AFYAAAAA
AAAAAACt/hwR/////wAAAAAAAAAAw3GQwv////96OAIAAAAAAEVjdQAAAAAAQWDlsMLeLVY9CtfD
R+ItVgcAAAAGCQAABgkAAFMHAAD5FQAANQBWAAAAAAAAAAAArf4cEf////8AAAAAAAAAAJPlEKr/
////PCgCAAAAAADfZ3IAAAAAAKwcWiTD3i1WCKwcOkriLVYIAAAAxAgAAMQIAAA5BwAAqxUAADUA
VgAAAAAAAAAAAHko8Y//////AAAAAAAAAADDcVL2/////5gqAQAAAAAAR8Y7AAAAAACTGAR2v94t
Vl66SWxL4i1WCQAAAJgEAACYBAAArQMAAAcLAAA1AFYAAAAAAAAAAAB86IRe/////wAAAAAAAAAA
w3FS9v////+xXQAAAAAAAI76FQAAAAAA7Xw/NbTeLVYUrkfBO+ItVgoAAABxAQAAcQEAAFoBAAAO
BAAANQBWAAAAAAAAAAAAovN/Vv////8AAAAAAAAAAMNxUvb/////LyABAAAAAABTYj4AAAAAAN9P
jTfB3i1WQ4tsB07iLVYLAAAAbwQAAG8EAADXAwAAggsAADUAAQAA"

dns='H4sIAJma4FYAA2NiYGDYDMSZBYkpKUUKwUHO8Z4BOiWZuakKIZ6+rvFunkHBIUh8H0cgtzQzr8TY
SME1zNUvJN7TBcYPCfXzc/WJdwYKBjg6e7uG6KTl5CeWwMQDXIPi/VzD4138fR09/TDlgkOdoFIg
8yxgUiGRAa46xSVFmXnpMCGIsnygs7MYYICRkYnxPxCA2OLLLoaB6N7lEJqPEUQ22Hc9trAHMk0Z
zE1MDM0szUzNjVKNDU3TUizN01INjc2Tk1OS08xMDC30knPy9dLy80sKgNaWpOQV6yXn5wINAQDH
G9mgLgEAAA=='

# output data:
hsout="H4sIACLZzVYAA9WWTUvDQBCG7/6Ksme77FeyaW/SD9pLEVsQlB6WuNRAu1uSraKl/92d1YsgZIm1
rJeQ7EwmMw8vb+Z43UML+6TRsPd4RKu3fbhD0619RT60dMpVjatKtUVreL4P4YXeaQXxmW0c5DSf
J5CyUDuogZ59qIEQOsHx5EUbt6o+Y4zQvE9Yn5IVo0NWDBl5gHJj3ZR1tXeVNZA2s3X1bo1T297e
1q7XlMpA2sgaM7IH43wSExxOtGr0z9W5/4AM1ae23il4B83HkxsSKimnN7Z+C1Pd6dIavPQfMZXZ
wDAwsT3U5Ree+a0IiZRixjBl/hpGvq2tsyHiyj1ah3mB4LceT1fHBFh7GqToyjrLRStrys7MmmHJ
A+siinXoMRHWZJixzrrmspU1yc7M2oMWmEosZJyuocc0WLPcA+nKmst2D+GDP/IQmkWxDj2mwdrr
WvDuui4uruuiwEximvtrpK6LlFh3/zdyennWEucEFzxW16HHNFh7D+nOWg4GF/cQMJAB+DWlUaxD
j2mwhn9jZ79m4vIeIjNMCbBmInLnS8lDfrOHtO98Z99DSGDtXZtEekhKO58Q/0nXNPOUcZ7FesiX
rj8AD6TlLTgOAAA="

vsout="H4sIAELZzVYAA92WzWrjMBCA730Ko3MrZmTZlnULaQu9hLAOW7pLKcIVxtBYQVa6lNB3X0k5FOqG
ZSGpifHJM5rRaD7mZ0fmyunG2Dcik9/kh65NR6tadV3bNeTxMiEL86yDbkdmTWPv287/EACJIAGI
P7B628QD5PbF/AmCyinX9q6t1Uv0UN1H9UKvtQr6142xrvd3PD1rp2tn7P4itQ5+PtTkPYhvXnXn
Vu1exwDzK2BXCCssJeSSwa8Yg7KNdvsw75Y83scpoxllGJ0vrXEmil29IY/Rc2W2ttafjIpoQwU7
ZBY+cq372rYb15qYjp/axucmIexk2/vcJav5MqkeFiG6W2PXKkRH7q5vZjFpc616/fWrGEoQ8VUh
oXOz7YIpZnCZvF/szpmXD4GJg7x80mlJ0/K/eAnheWFBWTomLywGvDhMghfPjsurFJRTLqjIRuOF
QqYwTV4o0yPXV17SgqKgrBizvrJhP2Q4DWD/LDAOZweMScDJAsNTdcRRN44sHQAT0+AF7ES88lE3
RDbglU1hQzw+L+73eVp4w4N99Dt4pcMJlk+DF+Ynqi8+an0N+2E2kX545PlVpN4GOc1HnV+sHG70
+/r6C3eawvjiEAAA"

aout="H4sIAG7azVYAA9WZ32vjOBDH3/evKH6+FZrR777tNbvQl14hhYVdlsOX+pZwbVxSd49S+r/fyFKa
xFLi6ik+kkCRZc/oO5+ORuOX6qLump/t+rk6P/teffpVL++Wf9Gve2azWTuvfvx2Vl21t42//FLN
v/bTrpr7pq7oSn3/cLf8e7mou2W7+vO26ZqF/yvcVd/7u/bnVK/+0udfzaq7WYbryEF9BP4R9Q23
51zR95t/9k29/tl0we7l6rpe/NN0F+3Tyg+hcZamXK/bru09erp98Pfcrh5725erL3ftv5vZTgg/
di37qVIwFMA0AxRx8u/PXbOZLKxFB7r3c94+rRfNxoXdRwI6ecyBP5661AMazFhKPLASgPej+4uO
NjfrAKcYgGAWGUq9sZrq1K8kK9/N80O/uMq76r2fdxSkx45ideef5z/VrHlcrJcPffAoWrOr+dl+
RGnOl3Z9X/sHV5ezz5+4H7po6scmH2Lk5wB9iPNqJMK9fniZIKag34EpHqVkgCm3u+FFYGAlk5qh
yoJqLOdcjoHKlSoBtfdhCGqwlHigrTIqB2qwWQYqyiyovYAnBNWkoL6pkQg3UVD5KKjKgns/qOAk
342vUYySKoAiUlWGVMuN4sqMkEpJ+WhOH5AanRigGk0lLoDi2uSSarRawqoXK8Nq1PCErLqE1a0c
qXQThdWOwypNweYPFvUerLT9K8nQMjAZVo3kUgo+xipqU8Jq8GHAajSVsirRIuRYDVbfliINQ3QM
mBUHSCWlcqQGAU9HKvKE1K0YqXATJdWNkiq4ggJSOeyGV9P+byyTBKrLgCpRCGNgbPunZFYCanBh
AGo0lf6voJDZ/T8YLcmpXqkMqVHASZG6VSNVbpqkIo6SKpU9ysmAKoV7myZQPqXdH5AiDDYDqxbK
OT4Kq7Ulh6roxQDWaCrNqkjwZY9VwWoJrV6tDK1RxBPSKhJat3Kk0v1vaVUajx5qhliZvePIWAWg
nQBU49UqL6oAeh+GFUAwlakAlBIHqlWeYRWkpE1CHigCdFxMVsNJwbrVI9VuorCKcVip3CqBVbqi
ctWRaKOwoixKrMGHpFztTWVgBWEwW67KvcS6KVc1LYUfYJW0yrEaJDwhqzpTsG7kSKWbJqvvKFjp
4FFQBjgJu/FFYJLTpkl1q8w2rBzRHDfOYxWr0QWsBh+GDatgKZPapcyWAMFmUcOKlMo1rIKAJyQ1
07B6UyMRbpqg8vEeAHBR0AMQci+8SPlUIAP6xU1zmNEkF7FxfhhUoY+2zAacBhcGnEZDiQNIg7mD
VTBZgqnXKYNplG9SLwC2YiS6TRNThPF86uTRZDbIp3bv2Kx9XKm4Q8OsznUAOJ1c+Hg+FUUvAGzm
TVW0lOZTOgjnGwCi+AUAKZXLp0HA04EqMg2ANzUS4V4//AcgAkTEUR0AAA=="

dnsout='H4sIACaX4FYAA3WRX2vDIBTF3/cpxOdWYpIma95K/0BfSqGBwUYZztyUQOLN1HTrSr/71JSxhw1f
1Hvu8dyfV7oUFk6oL7QgL3ShsBPthS1RKZC2QUWPE0J3WIGvX2l56cOOblr8oK50sMI2xjZStP7o
Gi0oG7oOT0G5gw6Er1XK2MH5tq8V2N/uovOeVH4xCUaBZcq3sB89vXnZ+uyMy2bUxhHPplE8jfOS
J0UyK/j82b9RCn0CO2bda7QYIgxVfw9Aj7dxIBts1p+i61sgWJPBQEUqN36jiHKJCpKnKc/m2SyP
IeGzuprnNfAkl7KSdZbyRyZbZDWi7XWjrDNnErvABAct78C2+zRE4IyzmPEw8P/B/KIrMFI3feBT
eKRdNygH2F+QkQjBM2iy2h0IvhnQZxfdxdbwPoCxxltuUHfCg6Db1XoRhb8BYeBvgCkvkiQA9P+6
xEH51jiPJuT28A24wZJ3JAIAAA=='

# The Test:
data=$(mktemp)
errors=0

# TEST OF HOSTSTATS2IDEA
# prepare stored input
echo -n "$hs" | base64 -d > "$data"
# generate output
./$srcdir/hoststats2idea.py -i "f:$data" -n hoststats --file /dev/stdout |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$hsout" | base64 -d | gunzip) ||
   # on error, print it and remember it
   { echo "hoststats2idea FAILED :-("; ((errors++)); }

# TEST OF VPORTSCAN2IDEA
# prepare stored input
echo -n "$vp" | base64 -d > "$data"
# generate output
./$srcdir/vportscan2idea.py -i "f:$data" -n vportscan --file /dev/stdout |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$vsout" | base64 -d | gunzip) ||
   { echo "vportscan2idea FAILED :-("; ((errors++)); }

# TEST OF AMPLIFICATION2IDEA
# prepare stored input
echo -n "$ap" | base64 -d > "$data"
# generate output
./$srcdir/amplification2idea.py -i "f:$data" -n amplification --file /dev/stdout |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$aout" | base64 -d | gunzip) ||
   { echo "amplification2idea FAILED :-("; ((errors++)); }

# TEST OF DNSTUNNEL2IDEA
# prepare stored input
echo -n "$dns" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/dnstunnel2idea.py -i "f:$data" -n cz.cesnet.nemea.dnstunnel --file /dev/stdout |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$dnsout" | base64 -d | gunzip) ||
   { echo "dnstunnel2idea FAILED :-("; ((errors++)); }

# cleanup
rm "$data"

# exit with right status
if [ "$errors" -gt 0 ]; then
   exit 1
else
   exit 0
fi

