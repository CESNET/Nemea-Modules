#!/bin/bash

test -z "${srcdir}" && export srcdir=.

. ${srcdir}/test.sh

./luatest "${lua_dir}/ip.lua"
