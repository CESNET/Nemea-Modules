#!/bin/bash

# input data:
in='
H4sIANzTd1gAA2NiAIPYzILElJQiBZfgkHjPAB0oLzjIGcQrycxNVQjx9HWNd/MMCg5B4vs4Arml
mXklxkYKrmGufiHxwc6OPq5gIUMzsGkB/kEhQAtWM5gxQIGokozQfyCA8XlZVBhhfA2BsggQLStY
FsEOpFl5EfpauM10kfUpmEjMh/F38kP0PQfql0fTh26fSJe5GYzfDLVPDmgfK0QfIwMAACTyOhQB
AAA=
'

# output data:
out='
H4sIAEnVd1gAA9VUwWrcMBC99yuEzonwSFbX8a3dJLCHhoVdKLTkoGinXlHbMpacEJb990pyCG7T
DdmkFGJfJN7MezOjx+zoXHmsbH9PS/KdrgbXGW3s4NgX02JPr08IvbIbjOiOru+7dKKXtb2jAfpc
K/2zNs6nwNXXBF5hgyqiTaTYoEft7QOVaiLBH8g+Qhe32Pq1GXGewew0g1OANWSlPCsl/xYZ16qv
0I/FLJZ5kuPARM54waBIGsveepsQrzt6vR9b8Il3ZYdeI1ksCQiWM/GRAWlMtfXkBokiqSwWhcbA
34UeUw7JxJ+eo9O96byxbVQ8rHMSzloNDonxRNu2DcPADfGWTDoqRfjI3dboLTGO/KhVVYUg5UYW
01aks7YmDvvbh9LngWpuhzaOaRbul7ZvVLzQxfnFpyyFoHL4t1lDmYlSztKs4xtPePYfdu/CK0WZ
wUGvgOAMgMmc5fIIs4QsyRnPGcizl/tlmnWMZZ5VO+yaaW9vtI2A1/gmE098E4nehXFCA1By8Y+X
DM8YiIJJGV7l5b6ZZh3jm2fV/se2ka/aNsUT18homl9vuSj/mgYAAA==
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "minerdetector" "minerdetector" "$in" "$out"

