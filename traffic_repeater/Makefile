# Author: Jan Neuzil
# Project: Cesnet modules
# neuzija1@fit.cvut.cz

CC		=  gcc
CFLAGS  = -Wall -pedantic -Wno-long-long -O2 -ggdb
LDLIBS	= -ltrap
TARGETS =  dir doc traffic_repeater
OBJECTS =  ./src/bin/traffic_repeater.o
DOXY    =  doxygen
EXE		=  ./traffic_repeater

all: $(TARGETS)

./src/bin/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c -o $@ $< $(LDLIBS)

./src/bin/traffic_repeater.o: ./src/traffic_repeater.h

dir:
	mkdir -p ./src/bin

doc: 
#	$(DOXY)

traffic_repeater: ./src/bin/traffic_repeater.o	
	$(CC) -o traffic_repeater ./src/bin/traffic_repeater.o $(LDLIBS)

clean:
	rm -rf ./src/bin
	rm -rf ./doc
	rm -f $(EXE)

