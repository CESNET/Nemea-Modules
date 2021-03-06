#!/bin/bash

# input data:
in='
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

# output data:
out='
H4sIAMUJM14AA+WXbYvcNhDH3/dTGL+ujEZPlvTqrns5OEjDwm1JaQlB1sPG1GsvtjeX5Mh3r6S9
QgvhLt6Sa8p6WYGlv0bS+OeZ8X25MrPfDuPHUhe/l5fz7Hf7uXo5bNu+fPNjUb4anE9D9+Xt6yx5
5XfelHHk/dDu34bRHNxb52dv53Y4Ttl83Ocp5XU33CXl7Wzmdppba7p0uxr62ffz0bzZJW1pP1XW
T72fqz7Zr5LxbLv8nGQv3scJm/aoJRgEwhQB3mClGdec/Zbsbsy49fPDZm/WmyFvQjKIF8b4QlWk
4hVojgXOi6/HYT6KpnZfvskr3R5s3MgUDt3KdN0UR3HsvR7GnUmmy5urF5c4H2o4jPbBNb9Mfrzc
pjNlJ06zH9vpj2L9068FQEWggi+tF3tu1izfR0X1lypu/Xocdrn/YVM/mw/r0Yf2w0vfb+d3cUgd
/divhkNeFSA5YGy9Owr/0X+VH88X3Ac4uY+K7L7V6CMKf1MphAnCfANMA9cMZ9XNVRqtgxWiwQY1
TDnEvCeooQIQOOJrJikw78q88mTHdp/R0PloxVVrOrTvTF9sD9HRbb8tP/9w///GMPoRS43pIxgS
kjCUDF/Iilas4s9F4FeQJ/8D8kCD0IwsJk9YIR0lgIStI3lGKGQgAApgTcBMcIvrMyIvBUDQBB4h
jybwVPxfuGFn2r6ynxawR8hS+F77ris2BBfv7uoKxx9nRbhTFaNVbAqM0zMVPLWKake+dWhU9ERA
OWjGFgMaHBbpQtiFgJhkCjUeO9QY2oDEUnplzw5QUE+GxtieBKhcyucTvMVgGOsEcjpv5DTeiMZE
M7k8FYvGe2YdMs6qmIoNRYYHgYIAR2tX88DPKSCmVKw0xo/xJnIqjgExVoT1910S0mdPzESn3Lyc
Q+pr4zH3SMkgEVNRq1hMzNYqsATiYKPOiMOv+DI5xj318GUC3y+G6l/Vh+RUDKmmfDGGzEgDYDGS
jecRQ9EgpeqAJJhQew+CqubMMHyqPqxz+mXPlH6XlIdMM/Gty0N2Mp+1xsv5JIE38Z1XyBvbIOY4
jWhygRhpHOPcGWFgCZ9/Ag1K2x7BEQAA
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "voipfraud" "cz.cesnet.nemea.voipfrauddetection" "$in" "$out"

