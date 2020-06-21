#!/bin/bash

# input data:
in='
H4sIAAAAAAAAA2NiAIPozILElJQiBZfgkHjPAB0oLzjIGcQrycxNVXANc/ULiQ/x9HXVKc3MKzE0
U3AMCXH1DQgJhvFBegP8g0JgfJBuEB9ofDKDHgMUcDEwMP4HAhifkYmZDcT//PfKjii//DAuBjGG
Syy41bMxMrGD+HdV2BKDlheGvfgLVs8IlgcAPUddmM4AAAA=
'

# output data:
out='
H4sIALsa714AA92SS2vdMBCF9/0VwuvKyLItP3ahaWgguQSuodCQhSyPHYEtGUluSS7575XkG0oW
fSy6afFG1pz5zgw6p+RKm4W7pEXJ9eXHC5K8D4fwS2uWQ9NnuGEDwUVWAa4Ja3DT81rkrB9yAUF9
CQ6E6+QCsYtkJc4ozoqO5m1WtyX5ElQfDHAHP1SUYMIwzTpSt5S2NN9VXjNp8+Q198mFc7CsLr3R
k1TJQ7SywsjVSa0C5XabnVxnQJuymxBg7bjN6Hj8hObQgvgOsIF80C4633LxKBWgG+BGSTWhRQ8w
IwNCT0o+w4CE4Cgjb5lveWg0ekFZStM8ZYhPXCrroq8F8xWMb0/DlwXjo96MCNb3p+TOaKfjbk6s
oWjtY1zs+q6I12dm8vASbjtuJnDnVm3iidJQ+T3odYKddPBL7pwD319APKd+OQUuVbAATz2gN5uD
UftplzlO/jmiDqF+9ujHIb62z8wc/bqnNYKTq1l/i02OO2mdFHwO3i/vTj9PmKhGGOqG4aocClzU
FfUJ4wLnnPBhhLzqC/6LhLHOx4vQtqz/wYSxkpA/CBlLQySqvxqyM/N/Ctl30+jQNccEAAA=
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "sshbruteforceml" "cz.cesnet.nemea.sshbruteforceml" "$in" "$out"

