SUBDIRS=. tests
bin_PROGRAMS=luamodule

luamodule_SOURCES=luamodule.c \
	luamodule.h \
	luafuncs.c \
	luafuncs.h \
	luahelper.c \
	luahelper.h \
	template.c \
	template.h \
	fields.c \
	fields.h
luamodule_LDFLAGS=-ltrap -lunirec -llua -ldl -lm

EXTRA_DIST=README.md example.lua
include ../aminclude.am
