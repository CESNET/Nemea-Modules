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
H4sIAPC94VYAA21RTWsDIRS891eI50Ti7ma32VvIB+QSAgkUWkKx+rYsrL6tumnTkP9eNaH0ULyo
82acGS90ITy8oz3TmrzQuUEtujNboDEgfYuGHkeEblFBxC/0cO7Tjq47/KQB2nvhW+dbKbp4DEQP
xifW/ilNbkGDiJgyzg9Bt3tV4P+qCx01qfxmEpwBz0yksN95eo1jq1MQPrS32WzCy/EkG2fVged1
Pq357Jkmpz7hqy+h+w4INmRwoIgKuVpDTHiqJlVR8HJWTqsMcj5t1KxqgOeVlEo2ZcEfmeyQNYi+
t63xwQaTqFNYHKy8N7HZFSkeZ5xljKckO4se0+2g+ntkeozu46JLcNK2fQpex660HkxoLl6QW1SC
J7Bkud0TfHNgT8F6sG3hYwDnXZRco9XCR/5muZpPUukgHPzfTMHrPE/NxA9b4GAiNasmI3J9+AEU
jVKp/QEAAA==
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "dnstunnel" "cz.cesnet.nemea.dnstunnel" "$in" "$out"

