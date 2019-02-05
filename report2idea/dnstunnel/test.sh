#!/bin/bash

# input data:
in='
H4sIAPD8jFcAA2NiAIPNmQWJKSlFCsFBzvGeATolmbmpCiGevq7xbp5BwSFIfB9HILc0M6/E2EjB
NczVLyTe0wXGDwn183P1iXcGCgY4Onu7huik5eQnlsDEA1yD4v1cw+Nd/H0dPf0w5YJDnaBSIPMs
YFIhkQGuOsUlRZl56TAhiDKgs/MZshiggJGRifE/EIDY4ssuhoHo3uUQmo8RRDbYdz22sAcyTRnM
TUwMzSzNTM2NUo0NTdNSLM3TUg2NzZOTU5LTzEwMLfSSc/L10vLzSwqA1pak5BXrJefnMjAyAADn
lUteLgEAAA==
'

# output data:
out='
H4sIAFueWVwAA4VRwWrcMBS89yuEzrGwZNmOfQu7G9jLEtiFQEsoivRcDLaeI8nbbkL+PZK2hBwK
PUpv3sy8mTe6UQF+obvQnvygdxZnNV3YBq0FHUa09OmG0AMaSPM3enzMuAPMoGicGOvDGrHTTwPh
y8bpsuQNej/h7wQ8BhVGH0atpvSMAgFsuLKrOWGpfmUavIXAbKJnn9z0PcF257hwGq9YUfKmKEUh
2hOv+qruefc98W7Bazcu2UefZOZ5tVE0fZArG8EzOLI9HAk+e3BnMGS0xMHLCj74RHKPblYh7e+3
u7sy+wXl4d/ikvdVlcU3DmKYX1BdQpX1icu+KntZZtQBQ57v/qh5mYDgQFYfTZgYfTRiYxo9aaXk
TdfUrYCK14Pp2gF41Wpt9NBIfsv0hGxADIsbbYhJMY1zzhlXp/+WtX+QuQPOOBOM57AfHAbMv6tZ
coNZlj7ljFNbG1xtOl60ZQ401fq/y/fbNG2a+rkuB12UXEEhBw7FrWig6LSqJBdGm07Q928fxh/D
UnQCAAA=
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "dnstunnel" "cz.cesnet.nemea.dnstunnel" "$in" "$out"

