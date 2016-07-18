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
hs="
H4sIAPD8jFcAA2NiAIOZmQWJKSlFCi7BIfGeATpQXnCQM4hXkpmbqhDi6esa7+YZFByCxPdxBHJL
M/NKjI0UXMNc/ULig50dfVzBQoZmYNMC/INCYHyQeXC+BVRHSGSAK1QgIMg/xN/Z30enuKQoMy9d
wc8/xJWBgdmRIZABCfwHAhibW4xHDMYvWb07DETrr9kd9hkqz8TGwCDMkJFflFmVn1eSmKMQHOmn
UJycmIfbSB5PHhkYX2YNxEgFIG3CRLaRvHyC+jA+D9RISSD9lnxXAj3OD+OzQz1uDTSylJFsIyOk
BaRhfGYkV74j35XhNsFwVzIgGfmcfCPFhAW5YXwBJI/LM5NtpDeXoASMz43kyh/ku5KLS0gEW4y/
It9IfhFHuMdZSHIlIwMA7bYFgOYDAAA=
"

vp="
H4sIAPD8jFcAA2NiAIOuzILElJQiBZfgkHjPAB0oLzjIGcQrycxNVQjx9HWNd/MMCg5B4vs4Arml
mXklxkYKAf5BIfHOfhC+oRnYKJAYjA8yDM63UHANc/ULiQ+JDHCFCgQE+Yf4O/v7MDAwRTNYMUAB
CxOr6H8ggPH1WUWDQPxDXzVsdLp2h0mwhOUt6d0dNg0o90p4txojG0IvIwenOrLeCFZBcRhfpXt3
mApbY+haoN4JjAwMHJO3b8enN4nFIBTEV9hQ9MIUqHeh67ZgNqhe81krJuLT68ouJA3i31Vhe5gF
1DsZ6OhrQL0mHAwM2gk6Z9H0amDTm5aW9qwQqPdhlci7m1C9fph60d0MDqt17g+jgoF6U6zv518E
6lVgZmDo4zlwkYDeMBBfu13M0g2o13LLiW3zgHrVmIBxcAO/f3WZ/KJA/Ns/606B9M4+ojDhEFBv
F1DvooTMQgL2hkD96xYC1OvJw5Q9H6j3CzCcPZPx2+vJyWcH4gfukHP1BOrV3TT3/E6g3kNAvTcu
ewQA9TIyAAD1MXY38QIAAA==
"

ap="
H4sIAPD8jFcAA2NiAIMjmQWJKSlFCi7BIfGeATpQXnCQM4hXmplXYmaiEOQaGO8UGeIaDBcIDoAK
lGTmpiqEePq6xrt5BgWHIPF9HIFckHpjIwXXMFc/oPEuMD7IQDcf//BgZIEAR2dv1xCEENAOVDVA
AWQ1hmZgZwb4B4UwMDCfZghjgALt52zV/4EAxj9cGPQNxO/zYATzl9hbg+lj3uacG+/phunfVTlm
/Ug3DCTLxwrBS5kZGN5xMTCYMiDMrdyh9xebufe5oeautQTT/r3T3+0Bmnvz3PdgR6C5TEAxeRYI
7gGauwTN3PXaxf+xuteHCcw3NK8G03lCzQe2Ac09cGrhUmegucwg93JC8BR2BobdYqjmrv0nI4hs
7uSnjMEg/lNdiLl9vwtg4fByH9BcoPFZLkBzgc5kuM0BwUpAc9NEUc213WQgjM29M6Ug4aA9ywFM
R1huydgPNPf3yo+TQOYCg5UhkgWCfwId/5ob1dyi61W3sJkbcw9ibix3Ipie+3652iGguVEp1vLu
QHPZgGIx7BD8A2jJc0H84XC4cMIhEL/KAhIOrsmlYNox4ekGkLm2XNcPg8wFGsfAxgnBwUDOT1FC
4SuwCsS30YCYez+9CEyvkYlSOQw0l2ONjJUX0FxgsDIc4YBgS6C5q9HMrdT42I8tHGZoQcLB/Rgk
/U6WYCkDhW/cLs8cb6C5QGcyzGCB4LXA8GVHC9+aFy1x2MzdGAvh9/0SBdNva+xNtwDNFVnnfhCU
L4DJlaGQEYKjgJiPBdXcRZ/rw7CZq68AcW9wkh0kPPx7zQ8CzXXuzmH3A5oLdB5DPgsEXwe6twni
XkYGAJhUtVSbBAAA
"

dns='
H4sIAPD8jFcAA2NiAIPNmQWJKSlFCsFBzvGeATolmbmpCiGevq7xbp5BwSFIfB9HILc0M6/E2EjB
NczVLyTe0wXGDwn183P1iXcGCgY4Onu7huik5eQnlsDEA1yD4v1cw+Nd/H0dPf0w5YJDnaBSIPMs
YFIhkQGuOsUlRZl56TAhiDKgs/MZshiggJGRifE/EIDY4ssuhoHo3uUQmo8RRDbYdz22sAcyTRnM
TUwMzSzNTM2NUo0NTdNSLM3TUg2NzZOTU5LTzEwMLfSSc/L10vLzSwqA1pak5BXrJefnMjAyAADn
lUteLgEAAA==
'

voip='
H4sIAPD8jFcAA52SzW7TQBCA1wlIqegFUbVXHxGKVuvfxL4Q194ES4lt2Ws3PSCrxQm1aEOVBFVC
ggtH7hx4Fi68Aa+QJ+ARYPyTNkW2VTEj7+x6dvebnZkWyoQ7T6/PkmTJWwGLba9brgLfzFbr9GrG
W5RRk9muEzN7Qot/2Swe2n7Auh/SxVoSeRpRB26wtuvItb146BuhFdtOZDMam27osAq359OhPY3p
1JjYjpGD6rYGoWnSIBiG49g0xuOdfYJaceWYOiP2Kvf3ywDZqUe7q/UyXbzdPZBf5J+CtarcQT5z
JzUu5lY4woD6sTECKELtr+gTqhEO5A9INve8TZRZ/3gTcWCflF8me+j53aFD0APUlwUQQshAwyJW
sKArRCXGaj1bpqt3vHc85QUBiwIW0HU9vnOL/35S4L+MNlGrCf8UdB+JYobvy2TQxxKWsbJLRt8e
8uBfcUE0jE3UBvu6JB7+S3wGSpCUATX4Bsn7q7N0gd98PJldXvJMJPzFTQ8TUEXm5zcaliUMA0+I
Lii6qmSjJumJiOZ1cXW4Vmsb18V5EddLiOsR2KMyrk5VXKjMBIx3caHPDe9vbznzpOD8gIw/bsr4
EegBEtU84/B+KHivueINDbd3m//fyf2G26/jFw1XvFMrG05owj+o/D9n98v/oinNUP5enmb5P8sv
67KKOPQXzBibh/kEAAA=
'

ipbl='
H4sIAPD8jFcAA2NiAAFGgcyCxJSUIgWX4JB4zwAdKC84yBnEK83MKzEzUXCKDHENhnFACp18HJ29
fTyDQ2CCPp5+3vFOniHxbp6uPi4wUZApCKUlmbmpCiGevq5ARUEofB9HqEnGRgquYa5+IfHBzo4+
rjChAKAJriEQBxiagR0Q4B8UAuODbIHzLRRcPIPQXGKhEBDkH+Lv7O8D5YY4B8S7+Ti6B8P4/nBW
iA8DA1MoQyIDFHAxMPH/BwIYfy77KjsQP4QBO2CC0p48TK+n8zwKg9GMoLCGKQIz4FbAjES30owJ
1Uh00HzglONSoNFJAhE7lwFpkDoOIA5g0H3OwCaNbAUuX6xgxGIukpUnyvbdnw802jRuV+YCqBWs
QKzzPIABzQpcvliBZiQ6SEtLWwYKoCsVL5fNgAYUXC1qQC26H2eBzQobAgG1p2RyxRneR2FbTpT9
A9GM8IA6fZ1AQMGsTOfAH1DAOJiJbgUnEJ++DgsoRgYAlKKG+nEDAAA=
'

bf='
H4sIAPD8jFcAA2NiAIPCzILElJQiheAg53jPAJ2SzNxUBRfXEFfnEE9/v/gQT19XndLMvBJjIwXX
MFe/kPhgZ0cfiJChmYJLcEh8gH9QCJhvoRAQ5B/i7+zvA+WGOwa5uALNiAxw1SkuKcrMS1fw8w9x
ZWBgNGYIYIACRiZmtv9A8PnvlR1RfvlhckAxMQY2JgYGHQZPK0MTcz0jU0M9Yz1DQyMdZJ4xEs9Y
x98Kv4ni5JjoAjORjZGJHWTiXRW2xKDlhWFVQLFmDpCJCkgmWuoZWhoA9aHy8ZvCI06kKYwMAFPH
08ewAQAA
'

# output data:
hsout="
H4sIAJX/jFcAA9WWTUvDQBCG7/6Ksme77FeyaW/SD9pLEVsQlB6WuNRAu1uSraKl/92d1YsgZIm1
rJeQ7EwmMw8vb+Z43UML+6TRsPd4RKu3fbhD0619RT60dMpVjatKtUVreL4P4YXeaQXxmW0c5DSf
J5CyUDuogZ59qIEQOsHx5EUbt6o+Y4zQvE9on5IVo0NWDBl5gHJj3ZR1tXeVNZA2s3X1bo1T297e
1q7XlMpA2sgaM7IH43wSExxOtGr0z9W5/4AM1ae23il4B83HkxsSKimnN7Z+C1Pd6dIavPQfMZXZ
wDAwsT3U5Ree+a0IiZRixjBl/hpGvq2tsyHiyj1ah3mB4LceT1fHBFh7GqToyjrLRStrys7MmmHJ
A+siinXoMRHWZJixzrrmspU1yc7M2oMWmEosZJyuocc0WLPcA+nKmst2D+GDP/IQmkWxDj2mwdrr
WvDuui4uruuiwEximvtrpK6LlFh3/zdyennWEucEFzxW16HHNFh7D+nOWg4GF/cQMJAB+DWlUaxD
j2mwhn9jZ79m4vIeIjNMCbBmInLnS8lDfrOHtO98Z99DSGDtXZtEekhKO58Q/0nXNPOUcZ7FesiX
rj8AZ2OAsDgOAAA=
"

vsout="
H4sIAAUAjVcAA92WzWrjMBCA730Ko3MrZmTZlnULaQu9hLAOW7pLKcIVxtBYQVa6lNB3X0k5FOqG
ZSGpifHJM5rRaD7mZ0fmyunG2Dcik9/kh65NR6tadV3bNeTxMiEL86yDbkdmTWPv287/EACJIAGI
P7B628QD5PbF/AmCyinX9q6t1Uv0UN1H9UKvtQr6142xrvd3PD1rp2tn7P4itQ5+PtTkPYhvXnXn
Vu1exwDzK8ArhBWWEnLJ4FeMQdlGu32Yd0se7+OU0YwyjM6X1jgTxa7ekMfouTJbW+tPRkW0oYId
MgsfudZ9bduNa01Mx09t43OTEHay7X3uktV8mVQPixDdrbFrFaIjd9c3s5i0uVa9/vpVDCWI+KqQ
0LnZdsEUM7hM3i9258zLh8DEQV4+6bSkaflfvITwvLCgLB2TFxYDXhwmwYtnx+VVCsopF1Rko/FC
IVOYJi+U6ZHrKy9pQVFQVoxZX9mwHzKcBrB/FhiHswPGJOBkgeGpOuKoG0eWDoCJafACdiJe+agb
IhvwyqawIR6fF/f7PC284cE++h280uEEy6fBC/MT1Rcftb6G/TCbSD888vwqUm+DnOajzi9WDjf6
fX39BSe/hm3iEAAA
"

aout="
H4sIABMBjVcAA9WZXWvcOBSG7/srgq+3QufoO3dtpoXcpIEJLGwpxTvxlqGTcZhxuoSQ/75HlubL
UscxDIyXNFBs2efoPU+OXskvxVXZVD/q1XNxefG1+PCrnC/Kv+eLefPMJpN6Wnz746K4qe8rf/ul
mP7ZDrupHqqyoDvlw+Ni/s98Vjbzevn9vmqqmf9feKp88E8djile/a1Pv6plczcP95GDes/de9R3
3F5yRf/+8u++K1c/qibEvV7elrOfVXNVPy39JTTO0pDbVd3UbUZP94/+mfvluo19vfy8qP/djHZC
+Gu3sh0qBUMBTDNAEQd/fG6qzWBhLTrQbZ7T+mk1qzYp7L8S0MljCXx5atIM6GImUpKBlQC8vXo4
6RhzMw9wigEIZpGh1G3Uu+fHNtviIz24JsWbarVJJxWwnWJW1+17/Bz8tKYNVW/dUBEX/n3+p5hU
69lq/thWlco4uZleHJaaxnyuVw+lf3FxPfn0gftLV1W5rvK1R34J0NY+L1Oi6Ou7lxHyC/oN/OJR
fDr8crtfdwQGVjKpGaoswcZyzmUfwVypIQS3OXQJDpGSDLRVRuUIDjFPRDDKLMGtsmck2KQEb2VK
FB0pwbyXYGXBvZ1gcJLvF94oRm0YQBHCKoOw5UZxZXoQpjZ+dBXoIByT6DAcQyUpgOLa5NpwjHoS
iL2KGYijuGeE2CUQ73RKNR0pxbafYmkG+AiwqA8oJiehJEPLwGQgNpJLKXgfxKjNEIhDDh2IY6gU
YokWIQdxiLqdijQM0TFgVgxFmCTMIRyUPR/CyBOEdyqlio4UYdeLsOAKBiDMYb/umqyEsUwSwS5D
sEQhjIE+J0HtbwjBIYUOwTFU+keEQmatRAh6ki7sJcwgHJUdFcI7mVJJx4kwYi/CUtmjAHVwU3iw
/gJ1YDISgFR6sBmKtVDO8V6KrR2yo4tZdCiOodI+jERldk8Xop4EYy9jBuOo7hkxFgnGO51STf+3
GCuNR3dUXd7MwV6oz0xoJwBVvyPmg8xEm0PXTIRQGTOhlPiNI+YZiEFKWlbkUD+h4yyz4o6K4p1Q
qagjpVj0U0zObQjF0g2yxI5E66UY5aBWHHJILHEbKkMxCINZSywPWvHGEmuaCh8KMYmYgzhoe0aI
dcYUb3RKNR0nxG8wxbTrGeAonIT9wiMwyWn9JW8ss+drjjCPS+0xV2z0AIhDDt3ztRApsxhImXUT
IeZpztdIwtz5WlD2jAhnzte2MiWKjpNg3n8yAVwMOJkQ8qDuSB1YIAP6jetvtwdKLuIHgN8TLPTR
E74OwCGFDsAxUJIA0sXcri6EPAm/XsAMv1HXUX3h2KmUCDpOfhH6O7CTR9tfpwPbg8289gUnA4mG
WZ07l+C0beL9HVgM+sJhM9/oYqS0A9MuPH8sIU73hYMkzHXgoOz5CBaZY4mtTImir+/+A54AAfhk
HgAA
"

dnsout='
H4sIAFIBjVcAA21RTWsDIRS891eI50Ti7ma32VvIB+QSAgkUWkKx+rYsrL6tumnTkP9eNaH0ULyo
82acGS90ITy8oz3TmrzQuUEtujNboDEgfYuGHkeEblFBxC/0cO7Tjq47/KQB2nvhW+dbKbp4DEQP
xifW/ilNbkGDiJgyzg9Bt3tV4P+qCx01qfxmEpwBz0yksN95eo1jq1MQPrS32WzCy/GEj7PqwPM6
n9Z89kyTU5/w1ZfQfQcEGzI4UESFXK0hJjxVk6ooeDkrp1UGOZ82alY1wPNKSiWbsuCPTHbIGkTf
29b4YINJ1CksDlbem9jsihSPM84yxlOSnUWP6XZQ/T0yPUb3cdElOGnbPgWvY1daDyY0Fy/ILSrB
E1iy3O4Jvjmwp2A92LbwMYDzLkqu0WrhI3+zXM0nqXQQDv5vpuB1nqdm4octcDCRmlWTEbk+/ABs
sNUz/QEAAA==
'

voipout='
H4sIAJ0BjVcAA+2WX2vbMBDA3/cpjJ4TIclyYuspWdJAoCuGZHRslCJsxRWzLSPLTf/Q715Jztge
RrIMMrplFhaW7053ln/c3TOYcSMKpR8BC76AqTGiagy8VIWswc0gAFcqF070DNaPjX8Ci1JtgRWt
DDeyNTLjpVvOVG1EbbzV6tprXolKcCe7V7K53Wje5be5MCIzUu2255XbFGRPMBNtLQysnQ10Bl7/
u/qL07+4ty7WsjciCI+GiAwxWqOE0YhF9LPztua6EKaPerVM18oHE1NsL4TQJIEERhCzCI2QjyLV
yvRKrWzAjfe06jIbUbvpyhkvy9ZKkdtaS5GnWmzkw0x1tXOC8SBwA8xFm2nZ+GBtdNZzMJe8HDYl
r4Ois5vJutidVP2jNVgoXXG3Asv5xRT5w1WdznYn/7EVeloIr2//UWuElu3XIH3/yZpDgiHuD32Z
LrSqvJJ/sUypX1gF+E3pZ5/6gT/0n3Qp6sLcWWkyCF7ePf8jbGDEUMxQuIcNQhwbMUWTGIaQwujv
xuIwDvH54uBSBWYE78EhdDQk9p7kquKyhtnTEUAQcgoikvBYIq5FWQZrgoK77RgiOyIabLYJpCG0
U4AQwxEbRW5OQpaT/0nkIDU4OZhE7Pxb1MSngIYcDc1+CGzasLWTnCsErpIkDKF9EIx8JbGpw3YZ
4zNsM8JzheMXWtA+QyS7FhS/FTbIn2EjOffqsb/nGPvqQd9Q9aBHg3FMy0EZHZ2k5XgFZQePZtQO
AAA=
'

ipblout='
H4sIABsCjVcAA92VwW7iMBCG730Ky2dq2SYOCbdCW4lLhVSkSq16yBp3ay3YKDFbsYh3X9sRJamb
bURh1aLkEHk845nxl/nXcJgZ8VPnK9gHD3CkTL4spFZooI0SBj52ALzRU+GsazhZLfwXvJ7pF2hN
g1nGf81kUW68vfPGGzEXmbPKxY+t/UnOjMjLcNncBYH8D+KisIcg5RxQuHvjtl/9FspMZOlDMYnP
MT0nZIJxHyd9xu6hT9F4+61e5lyA0RgQ1kM9RHoYxRS8ZAV40ks1BVqB11OQ8yw93pRXKX40jvwS
wQgjigjzq+NcG+3XJZ8v4OOmA0J3u284rAepJPV+HL9o8xNmaPM11kQ6wD3wUhQ8lwtjL8dVWq/v
WfJnIAtX3r1YFrsaAddKCW7EFBgNXovwpV/rfJ65I+Do8uoC+3xFVoiPmj1YGbHNLok6YHO2/tYU
pfatUWRbbaTKXKsPhdKOhbHOXeMeEtySDMObAKuGYylJSBtgy3AhZ0kDZ9swb0hqh98+nKV9ggPO
WByfBGjdI4+rKg64PQ7/Hl97Ihsyxr7KLLM3EQWMRfQEhlkgiUcdZu2FrWl+tdTXkCX6VeaV7Xgc
sETi5NuzRKLtX9LEUkwRpV2URojFR1PG6iH7SSOjUfc/SmO9K4dkbXcjNW3s0RNkraKNh8DsE0Ds
JY4fUhtiljZg1pKnw8nj+5hRwojj7C/I+zS3Mw4AAA==
'

bfout='
H4sIAF6IaVcAA9WRT2sCMRDF7/0UIecS1rVV7E38QwVdlu7SHopIGke7sJssyaTFit+9SbTgYSlU
9lBvw7zMmzf57W8JHXGErdI7+kBe6RARqhrZXG0LSZdOzrneAnpxT1OlQxXHXkm1QhWmUNTUNYx5
p8uDl6al+hwpK/3rbuQaYzBCFzUWSroWXdgSi7oEYqWxQoAxG1uS0i8l/BjBECVJlj1646nSFfde
dDaeDCPfypTVAo6xZuldiNFhMeuyHv09nKsTtT6N5rs6VCFx8EWOhcFC8DL4ZC9BTqAC7vU3bRFW
G+WWr9aAIFDp8DDhlXei4ou5eyQgk36GNQ74HIeb/YW/3208EKF0W1sGkE/mySRvi8F5xOvH0OkP
Gq/8qPS6buDQiePLQTwvnsbpHzj0mCfRb+ZwlvDqMdwPoqj5SClah5CMWkPwk+7/APgGp9Q9XQ0G
AAA=
'

# The Test:
data=$(mktemp)
errors=0

# TEST OF HOSTSTATS2IDEA
# prepare stored input
echo -n "$hs" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/hoststats2idea.py -i "f:$data" -n hoststats --file /dev/stdout | tee hoststatsnemea.idea |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$hsout" | base64 -d | gunzip) ||
   # on error, print it and remember it
   { echo "hoststats2idea FAILED :-("; ((errors++)); }

# TEST OF VPORTSCAN2IDEA
# prepare stored input
echo -n "$vp" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/vportscan2idea.py -i "f:$data" -n vportscan --file /dev/stdout | tee vportscan.idea |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$vsout" | base64 -d | gunzip) ||
   { echo "vportscan2idea FAILED :-("; ((errors++)); }

# TEST OF AMPLIFICATION2IDEA
# prepare stored input
echo -n "$ap" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/amplification2idea.py -i "f:$data" -n amplification --file /dev/stdout | tee amplification.idea |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$aout" | base64 -d | gunzip) ||
   { echo "amplification2idea FAILED :-("; ((errors++)); }

# TEST OF DNSTUNNEL2IDEA
# prepare stored input
echo -n "$dns" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/dnstunnel2idea.py -i "f:$data" -n cz.cesnet.nemea.dnstunnel --file /dev/stdout | tee dnstunnel.idea |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$dnsout" | base64 -d | gunzip) ||
   { echo "dnstunnel2idea FAILED :-("; ((errors++)); }

# TEST OF VOIPFRAUDDETECTION
# prepare stored input
echo -n "$voip" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/voipfraud2idea.py -i "f:$data" -n cz.cesnet.nemea.voipfrauddetection --file /dev/stdout | tee voipfraud.idea |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$voipout" | base64 -d | gunzip) ||
   { echo "voipfraud2idea FAILED :-("; ((errors++)); }

# TEST OF IPBLACKLISTFILTER
# prepare stored input
echo -n "$ipbl" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/ipblacklist2idea.py -i "f:$data" -n cz.cesnet.nemea.ipblacklistfilter --file /dev/stdout | tee ipblacklist.idea |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$ipblout" | base64 -d | gunzip) ||
   { echo "ipblacklist2idea FAILED :-("; ((errors++)); }

# TEST OF BRUTEFORCE
# prepare stored input
echo -n "$bf" | base64 -d | gunzip > "$data"
# generate output
./$srcdir/bruteforce2idea.py -i "f:$data" -n cz.cesnet.nemea.brute_force_detector --file /dev/stdout | tee bruteforce.idea |
   # clean it from variable info
   sed 's/"CreateTime": "[^"]*"//g; s/"DetectTime": "[^"]*"//g; s/"ID": "[^"]*"//g' |
   # compare it with prepared expected data (previously base64 encoded and gzipped)
   diff -u - <(echo -n "$bfout" | base64 -d | gunzip) ||
   { echo "bruteforce2idea FAILED :-("; ((errors++)); }

# cleanup
rm "$data"

# exit with right status
if [ "$errors" -gt 0 ]; then
   exit 1
else
   exit 0
fi

