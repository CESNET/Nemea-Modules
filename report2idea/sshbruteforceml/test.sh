#!/bin/bash

# input data:
in='
H4sIAAAAAAAAA2NiAIPozILElJQiBZfgkHjPAB0oLzjIGcQrycxNVXANc/ULiQ/x9HXVKc3MKzE0
U3AMCXH1DQgJhvFBegP8g0JgfJBuEB9ofDKDHgMUcDEwMP4HAhifkYmZDcT//PfKjii//DAuBjGG
Syy41bMxMrGD+HdV2BKDlheGvfgLVs8IlgcAPUddmM4AAAA=
'

# output data:
out='
H4sIAIAo714AA92SS2vcMBSF9/0VwuvKSPJjbO9C09BAMgTGUEjIQtZcOwJbMpLcNhny3yvJDiWL
PhbZpHgjS+d+517pnJILbSbukgYll+efz0jyMSzCrxBdJ7q+xhnNC5x3Ncd813GcZXVRAGWkhF1Q
n4MD4Vo5QahihBaYMkzzlmUNrZqC3AbVJwPcwS8VI5iUmNGW1A3zqnJVec2gzaPX3CVnzsE0u/RK
D1Il99HKCiNnJ7UKlOtldHIeAS3KLkKAtf0yosPhCxpDCeIrwAbyXrvofM3Fg1SAroAbJdWAJn2E
ERkQelDyCY6Iz7PRP1JEyWvuaybqjZ4QTVmapSXiA5fKuuhtwXwD48vT8NFgftCLEcH+7pTcGO10
nM+JORxa+xCHu7zJ4/bGTO6fw27LzQBuK9UmrhgLJ38HvXSwkvZ+0JWz5+sriKfUD6fApQom4KkH
dGZx0Gvf7TTGzr9G1D6cbx5df4wv7nMzRr/2cY7g5GLU32OR405aJwWPjO3KX248tPP84fT74FU1
FZmoa5wzznDelxWuRCkwr2tSHWlddhn/Q/DK1qeOsKao3mnwyoKQf8hemYak7N40exvzP8/eT4An
GEb1BAAA
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "sshbruteforceml" "cz.cesnet.nemea.sshbruteforceml" "$in" "$out"

