include ../aminclude.am

bin_PROGRAMS=logger
logger_SOURCES=logger.c fields.c fields.h
logger_LDADD=-lunirec -ltrap -lpthread

pkgdocdir=${docdir}/logger
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

mansources := $(addprefix $(srcdir)/,$(nemea_logger_SOURCES))
nemea_logger.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=nemea_logger.1

CLEANFILES+=nemea_logger.1
