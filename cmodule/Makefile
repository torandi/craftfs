CFLAGS=-Wall `pkg-config fuse --cflags --libs`

all: msfs

msfs: msfslib.o io.o
	g++ $(CFLAGS) msfslib.o io.o -o msfs

io.o: io.h io.cpp
	g++ $(CFLAGS) -c io.cpp -o io.o

msfslib.o: msfslib.cpp msfslib.h
	g++ $(CFLAGS) -c msfslib.cpp -o msfslib.o
