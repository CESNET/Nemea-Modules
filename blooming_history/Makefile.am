bin_PROGRAMS=blooming_history test_blooming_history

blooming_history_SOURCES= blooming_history.c \
	blooming_history_functions.c blooming_history_functions.h \
	fields.c fields.h \
	libbloom/bloom.c libbloom/bloom.h \
	libbloom/murmur2/MurmurHash2.c libbloom/murmur2/murmurhash2.h
blooming_history_LDADD=-ltrap -lunirec -lcurl -lm
blooming_history_CFLAGS=-Ilibbloom/ -Ilibbloom/murmur2

test_blooming_history_SOURCES=test_blooming_history.c \
	blooming_history_functions.c blooming_history_functions.h \
	fields.c fields.h \
	libbloom/bloom.c libbloom/bloom.h \
	libbloom/murmur2/MurmurHash2.c libbloom/murmur2/murmurhash2.h
test_blooming_history_LDADD=-ltrap -lunirec -lcurl -lm
test_blooming_history_CFLAGS=-Ilibbloom/ -Ilibbloom/murmur2

pkgdocdir=${docdir}/blooming_history
pkgdoc_DATA=README.md libbloom/README libbloom/LICENSE libbloom/murmur2/README
include ../aminclude.am
