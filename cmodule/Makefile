CFLAGS=-Wall `pkg-config fuse --cflags --libs`

all: msfs

msfs:
	g++ $(CFLAGS) msfslib.cpp -o msfs
