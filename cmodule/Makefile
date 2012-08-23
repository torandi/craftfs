CFLAGS=-Wall `pkg-config fuse --cflags` -g
LDFLAGS=-Wall `pkg-config fuse --libs --cflags` -g

all: cli msfs

.PHONY: all

clean:
	rm -f *.o cli msfs

cli: msfslib.o io.o cli.o
	g++ msfslib.o io.o cli.o $(LDFLAGS) -o cli

msfs: msfslib.o io.o msfs_main.cpp msfs.cpp
	g++ msfslib.o io.o msfs_main.cpp $(LDFLAGS) -o msfs

io.o: io.h io.cpp
	g++ $(CFLAGS) -c io.cpp -o io.o

cli.o: cli.cpp
	g++ $(CFLAGS) -c cli.cpp -o cli.o

msfslib.o: msfslib.cpp msfslib.h
	g++ $(CFLAGS) -c msfslib.cpp -o msfslib.o
