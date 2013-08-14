CC=gcc
CXX=g++
CFLAGS=-std=c99 -g -fopenmp
LDFLAGS=-fopenmp
LDLIBS=../../unirec/unirec.o -ltrap

MODULES=logger

# Uses default rules
all: ${MODULES}

clean:
	rm -f *.o ${MODULES}

