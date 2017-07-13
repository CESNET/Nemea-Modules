ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=link_traffic
bin_SCRIPTS=link_traff2json.py
link_traffic_SOURCES=link_traffic.c fields.c fields.h
link_traffic_LDADD=-lunirec -ltrap -lpthread
EXTRA_DIST=README.md link_traffic.sup link_traff_conf.cfg.example
pkgdocdir=${docdir}/link_traffic
pkgdoc_DATA=README.md
SUBDIRS=munin
muninsupdir=${nemeasupdir}/munin
muninsup_DATA=link_traffic.sup
include ../aminclude.am

confdir=${pkgsysconfdir}/link_traffic
conf_DATA=link_traff_conf.cfg.example

