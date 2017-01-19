include ../aminclude.am

bin_PROGRAMS=logger
logger_SOURCES=logger.c fields.c fields.h
logger_LDADD=-lunirec -ltrap -lpthread

pkgdocdir=${docdir}/logger
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

nemea_logger.1: logger.c
	$(TRAP2MAN) logger.c > nemea_logger.1

man_MANS=nemea_logger.1

CLEANFILES+=nemea_logger.1
