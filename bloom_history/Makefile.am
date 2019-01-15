bin_PROGRAMS=bloom_history # test_bloom_history

# Devel
# prefix_tags_CFLAGS=-g -O0 -fsanitize=address -fno-omit-frame-pointer -DDEBUG=1

AM_CPPFLAGS=-I$(srcdir)/libbloom -I$(srcdir)/libbloom/murmur2

EXTRA_DIST=bloom_history.h bloom_history_config.h bloom_history_functions.h

bloom_history_SOURCES= bloom_history.c \
	bloom_history_functions.c bloom_history_functions.h \
	bloom_history_config.c bloom_history_config.h \
	fields.c fields.h \
	libbloom/bloom.c libbloom/bloom.h \
	libbloom/murmur2/MurmurHash2.c libbloom/murmur2/murmurhash2.h
bloom_history_LDADD=-lcurl -lm -ltrap -lunirec

# FIXME Fails rpmbuild if we do not include this in the rpm
# test_bloom_history_SOURCES=test_bloom_history.c \
# 	bloom_history_functions.c bloom_history_functions.h \
# 	fields.c fields.h \
# 	libbloom/bloom.c libbloom/bloom.h \
# 	libbloom/murmur2/MurmurHash2.c libbloom/murmur2/murmurhash2.h
# test_bloom_history_LDADD=-lcurl -lm

pkgdocdir=${docdir}/bloom_history
dist_pkgdoc_DATA=README.md

libbloomdocdir=${pkgdocdir}/libbloom
dist_libbloomdoc_DATA=libbloom/README libbloom/LICENSE

murmur2docdir=${pkgdocdir}/murmur2
dist_murmur2doc_DATA=libbloom/murmur2/README

include ../aminclude.am
