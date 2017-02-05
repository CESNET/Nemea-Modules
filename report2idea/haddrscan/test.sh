#!/bin/bash

# input data:
in='
H4sIAEh6k1gAA2NiAIOazILElJQiheAg53jPAJ2SzNxUhRBPX9d4N8+g4BAkvo8jkFuamVdibKTg
6OISFO/sB+Ebmim4BIfEB/gHwfkgw+B8CwXXMFe/kPiQyABXqEBAkH+Iv7O/DwMDkw2DFgMUHFjB
wP0fCFjC+HxdqiZHTHXufuMKpI2AcgEMM44wsmGqTbG+v94ZQ+2yR9jUwsw9c+YMklq7ydjUPqwS
WYdp7q5r2NQ+Xjo7BdO9WgvwuQFVbdQafGrjdnkiqe17Srxav7nEuyFoLTa1AhGWUzDD4cJ+4s2t
6sOm1vq+Pxa1YuuJN5fvBCMbANHH1dbEAgAA
'

# output data:
out='
H4sIAHx7k1gAA+2XzWvDIBTA7/srgucuPI35vJW0Zb2UsATKNsqQRDKhjcXYja70f1+0h7FDb7sI
Eg+J7/m+fjw1F1QyzXupzqgI3tAzb+UQ1i0bBjH0aDcL0EZ23MguaN73aiuG6QMBFBgKADQpNOej
VUCrvfwyE7VmWoxatGxvLdRbK97wA2dG/sG6To2Tj/eOa95qqW6O2MHY+RWjq5lefvJBN+ImI4DT
RyDTaHBWkGnAq42BqZ7rW5iVVPYtA7O8UlJL61+3R7SzJmt5Ui3/qx1DRDIjXFfUquOchDjJQggx
RncsmQct+NgqcdRC2tI8SSW+5aDZPjBJBKdxqmTQlFVQv2xMrCupDsz4ROvFcm5LWHI28vs5Ypuj
KW8pT4NZGsMsuD5cHIeH8/+ClwEhHp6bnRelSU49PEc7j+YpeHhudh7FAH7bdBUexf7McxVenKVJ
4uG5CY8C8Wees/Bo5OG5etukOQb/q+Bo50UJTT08R+FRmvnbpqvwYkywa533A2mPe+qZFgAA
'

. ../test.sh

test_conversion "haddrscan" "haddrscan" "$in" "$out"

