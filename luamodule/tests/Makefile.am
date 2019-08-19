check_PROGRAMS=luatest
TESTS=add.sh del.sh get.sh set.sh type.sh ip.sh

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

EXTRA_DIST=add.sh add.lua del.sh del.lua get.sh get.lua set.sh set.lua type.sh type.lua ip.sh ip.lua

include ../../aminclude.am
