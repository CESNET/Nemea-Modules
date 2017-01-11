include ../aminclude.am
ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=link_traffic
link_traffic_SOURCES=link_traffic.c fields.c fields.h
link_traffic_LDADD=-lunirec -ltrap -lpthread
munindatadir=${datadir}/munin/plugins/
munindata_SCRIPTS=link_traffic
EXTRA_DIST=README.md link_traffic
doc_DATA=README.md
