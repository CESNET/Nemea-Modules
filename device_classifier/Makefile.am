bin_PROGRAMS=device_classifier
SUBDIRS=libsvm
device_classifier_SOURCES=device_classifier.c device_classifier.h fields.c fields.h
device_classifier_LDADD=libsvm/svm.o -lunirec -ltrap -lm -lnemea-common -L/usr/lib64 -lstdc++
pkgdocdir=${docdir}/device_classifier
pkgdoc_DATA=README.md
EXTRA_DIST=README.md
include ../aminclude.am
