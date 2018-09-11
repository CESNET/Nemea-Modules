bin_PROGRAMS=blooming_history # test_blooming_history

AM_CPPFLAGS=-I$(srcdir)/libbloom -I$(srcdir)/libbloom/murmur2

blooming_history_SOURCES= blooming_history.c \
	blooming_history_functions.c blooming_history_functions.h \
	fields.c fields.h \
	libbloom/bloom.c libbloom/bloom.h \
	libbloom/murmur2/MurmurHash2.c libbloom/murmur2/murmurhash2.h
blooming_history_LDADD=-lcurl -lm -ltrap -lunirec

# FIXME Fails rpmbuild if we do not include this in the rpm
# test_blooming_history_SOURCES=test_blooming_history.c \
# 	blooming_history_functions.c blooming_history_functions.h \
# 	fields.c fields.h \
# 	libbloom/bloom.c libbloom/bloom.h \
# 	libbloom/murmur2/MurmurHash2.c libbloom/murmur2/murmurhash2.h
# test_blooming_history_LDADD=-lcurl -lm

pkgdocdir=${docdir}/blooming_history
dist_pkgdoc_DATA=README.md

libbloomdocdir=${pkgdocdir}/libbloom
dist_libbloomdoc_DATA=libbloom/README libbloom/LICENSE

murmur2docdir=${pkgdocdir}/murmur2
dist_murmur2doc_DATA=libbloom/murmur2/README

include ../aminclude.am
