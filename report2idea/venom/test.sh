#!/bin/bash

# input data:
in='
H4sIAKFLp1gAA2NiAIP7mQWJKSlFCi7BIfGeATpQXnCQM4hXmplXYmai4BQZ4hoM4/h4+nnHO3mG
xLt5uvq46JRk5qYqhHj6ugL5QcEhSHwfRyAXpMnYSCHA0dnbNQRihqEZ2LIA/6AQGB9kHZxvoeDi
GYRkA0QsIMg/xN/Z3wfKDXEOiHfzcXQPhvH94awQmJowVz9/X6AXFzP4MUABIxD8BwIYnwkIQHxX
mDyUFoiw/DLzz7IIGA0SN2XYcIpRkIHBlpnK5v0HKgMA3CPmo44BAAA=
'

# output data:
out='
H4sIAF4IM14AA+1TTU/bQBC991eMfC02Xm+M7Ug9QKBSDqQRRFRqhdCyHier4F13PSEKEf+9u2tK
qVqJC+oJrSxZM++9+d5HE0G4NHYXjeF7NNVkN70yOjkxpJGiA4jOxd1WWEwujKG1ouja2WamRk/Y
R5dfA3GGLQqPvkdt2psaCSUZG8CLXRfA0VzI9aB5Op8OOqL1rkg+JBJ7FzDRXigJKtGjh5y5f1qo
AZelrIjTLGbFgvExL8ZZ9S3oYS+t6shl7mHHRNh2BGRASFL3rkS4Opt9OQc7FAFGA0uG5/mfjW0F
eer09Ow49aYJih5fizsxulE1aulRacK9yaIL94JYeWKaL9honPNxfhSIM0PBfzyk5/KGrehBDIlj
Dbc74NCFhvWwVbSC3sqbzliCj0Cyu+nxB3wClmUsgSmB6mGj19psNagGaIXPpTpPZ7F3XfRVew8J
u0SCVsiV0hgacGk2Vj6N9Hlev3dgMgnjmrvw3pOzsiy9YTofBWSWhDeArCETrJu6i64fD+BvyT/E
+Eulp6n8U8nbTnaEE7PRnnpUeVDo0S8TC8vgl++10V1gE6RXRF0/PjzcqrVKcOm+Tfg/vAqb/HLr
p6dekJeYFyLN41IyHo9KLmNRNSJmvGyaPC+y2xyjxw/798t6w8uq3vSyxNNlDYfViqWS0JNVeglK
O9/uzoj6/az+61mlowYzVpXxLWuKeFRwHgvkVVxXrKqKmolRmruz+gmZKGzrsQYAAA==
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "venom" "venom" "$in" "$out"

