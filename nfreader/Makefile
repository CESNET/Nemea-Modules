CC=gcc
CXX=g++
CFLAGS=-std=c99 -O2
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=../../unirec/unirec.o -ltrap -lcommlbr -lrt


MODULES=nfdump_reader nfdump_reader_test

all: ${MODULES}

nfdump_reader: nfdump_reader.o
	$(CC) ${LDFLAGS} -o nfdump_reader nfdump_reader.o ./nfreader.so ${LDLIBS}

nfdump_reader_test: nfdump_reader_test.o
	$(CXX) ${LDFLAGS} -o nfdump_reader_test nfdump_reader_test.o ./nfreader.so ${LDLIBS}

clean:
	rm -f *.o ${MODULES}
	@for i in $(SUBDIRS) ; do $(MAKE) -C $$i clean ; done

