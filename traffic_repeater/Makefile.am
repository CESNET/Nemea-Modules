bin_PROGRAMS=traffic_repeater
traffic_repeater_SOURCES=traffic_repeater.c traffic_repeater.h
traffic_repeater_LDADD=-ltrap -lrt
pkgdocdir=${docdir}/traffic_repeater
dist_pkgdoc_DATA=README.md

traffic_repeater.1: traffic_repeater.c
	$(TRAP2MAN) traffic_repeater.c > traffic_repeater.1

man_MANS=traffic_repeater.1

CLEANFILES+=traffic_repeater.1
