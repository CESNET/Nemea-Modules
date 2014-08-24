CC = gcc
FLEX = flex
BISON = bison

all: parser.tab.c lex.yy.c

lex.yy.c: scanner.l parser.tab.h
	$(FLEX) $<

parser.tab.h: parser.tab.c

parser.tab.c: parser.y
	$(BISON) -d $<

.PHONY: clean
clean:
	 rm -f lex.yy.c parser.tab.c parser.tab.h parser

