#!/bin/bash

# input data:
in='
H4sIAPD8jFcAA2NiAIPCzILElJQiheAg53jPAJ2SzNxUBRfXEFfnEE9/v/gQT19XndLMvBJjIwXX
MFe/kPhgZ0cfiJChmYJLcEh8gH9QCJhvoRAQ5B/i7+zvA+WGOwa5uALNiAxw1SkuKcrMS1fw8w9x
ZWBgNGYIYIACRiZmtv9A8PnvlR1RfvlhckAxMQY2JgYGHQZPK0MTcz0jU0M9Yz1DQyMdZJ4xEs9Y
x98Kv4ni5JjoAjORjZGJHWTiXRW2xKDlhWFVQLFmDpCJCkgmWuoZWhoA9aHy8ZvCI06kKYwMAFPH
08ewAQAA
'

# output data:
out='
H4sIAF6IaVcAA9WRT2sCMRDF7/0UIecS1rVV7E38QwVdlu7SHopIGke7sJssyaTFit+9SbTgYSlU
9lBvw7zMmzf57W8JHXGErdI7+kBe6RARqhrZXG0LSZdOzrneAnpxT1OlQxXHXkm1QhWmUNTUNYx5
p8uDl6al+hwpK/3rbuQaYzBCFzUWSroWXdgSi7oEYqWxQoAxG1uS0i8l/BjBECVJlj1646nSFfde
dDaeDCPfypTVAo6xZuldiNFhMeuyHv09nKsTtT6N5rs6VCFx8EWOhcFC8DL4ZC9BTqAC7vU3bRFW
G+WWr9aAIFDp8DDhlXei4ou5eyQgk36GNQ74HIeb/YW/3208EKF0W1sGkE/mySRvi8F5xOvH0OkP
Gq/8qPS6buDQiePLQTwvnsbpHzj0mCfRb+ZwlvDqMdwPoqj5SClah5CMWkPwk+7/APgGp9Q9XQ0G
AAA=
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "bruteforce" "cz.cesnet.nemea.brute_force_detector" "$in" "$out"

