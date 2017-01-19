include ../aminclude.am

ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=proto_traffic
proto_traffic_SOURCES=proto_traffic.c fields.c fields.h
proto_traffic_LDADD=-lunirec -ltrap -lpthread

EXTRA_DIST=README.md proto_traffic.sup
pkgdocdir=${docdir}/proto_traffic
pkgdoc_DATA=README.md

SUBDIRS=munin

muninsupdir=${nemeasupdir}/munin
muninsup_DATA=proto_traffic.sup

