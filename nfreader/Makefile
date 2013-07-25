CC=gcc
CXX=g++
CFLAGS=-O2
CXXFLAGS=-O2
#CFLAGS=-g
#CXXFLAGS=-g
LDFLAGS=
LDLIBS=../../unirec/unirec.o -ltrap


MODULES=nfdump_reader nfdump_reader_test

all: ${MODULES}

nfdump_reader.o: nfdump_reader.c
	$(CXX) $(CFLAGS) -c -o nfdump_reader.o nfdump_reader.c

nfdump_reader: nfdump_reader.o
	$(CXX) ${LDFLAGS} -o nfdump_reader nfdump_reader.o ./nfreader.so ${LDLIBS}

nfdump_reader_test: nfdump_reader_test.o
	$(CXX) ${LDFLAGS} -o nfdump_reader_test nfdump_reader_test.o ./nfreader.so ${LDLIBS}

clean:
	rm -f *.o ${MODULES}
	@for i in $(SUBDIRS) ; do $(MAKE) -C $$i clean ; done

