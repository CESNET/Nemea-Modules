CC=gcc
CXX=g++
CFLAGS=-O2 -std=c99
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=../../unirec/unirec.o -ltrap


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=anonymizer

all: ${MODULES}

anonymizer: anonymizer.o panonymizer.o rijndael.o
	$(CC) ${LDFALGS} -o anonymizer anonymizer.o panonymizer.o rijndael.o ${LDLIBS}

anonymizer.o: anonymizer.c
	$(CC) ${CFLAGS} -c anonymizer.c -o anonymizer.o

panonymizer.o: panonymizer.c panonymizer.h
	$(CC) ${CFLAGS} -c panonymizer.c -o panonymizer.o

rijndael.o: rijndael.c  rijndael.h
	$(CC)  ${CFLAGS} -c rijndael.c -o rijndael.o

doxygen:
	doxygen anonymizer.c


clean:
	rm -f *.o ${MODULES}

