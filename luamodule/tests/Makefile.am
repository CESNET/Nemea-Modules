check_PROGRAMS=luatest
TESTS=add.sh del.sh get.sh set.sh type.sh ip.sh mask.sh stats.sh

luatest_SOURCES=luatest.c \
	luatest.h \
	../luamodule.h \
	../luafuncs.c \
	../luafuncs.h \
	../luahelper.c \
	../luahelper.h \
	../template.c \
	../template.h \
	fields.c \
	fields.h
luatest_LDFLAGS=-lunirec -llua -ldl -lm

EXTRA_DIST=add.sh \
	del.sh \
	get.sh \
	set.sh \
	type.sh \
	ip.sh \
	mask.sh \
	stats.sh \
	test.sh \
	lua/add.lua \
	lua/del.lua \
	lua/get.lua \
	lua/set.lua \
	lua/type.lua \
	lua/ip.lua \
	lua/mask.lua \
	lua/stats.lua \
	unirec/mixed.ur \
	reference/mask.txt \
	reference/stats.txt

include ../../aminclude.am

clean-local:
	rm -rf output/
