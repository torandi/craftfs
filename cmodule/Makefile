CFLAGS=-Wall `pkg-config fuse --cflags --libs`

all: msfs

msfs: msfslib.o

msfslib.o:
	g++ $(CFLAGS) -c msfslib.cpp -o msfslib.o
