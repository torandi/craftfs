#include "io.h"

#include <cstdlib>
#include <cstdio>
#include <sys/errno.h>

static FILE * file;

int init_io(const char * option) {
	file = fopen(option, "r+");
	if(file == NULL) 
		return -EIO;
	else
		return 0;
}

int io_read(addr_t addr, char * data) {
	if(fseek(file, addr * BLOCK_SIZE, SEEK_SET)) {
		printf("fseek error in io_read\n");
		return -EIO;
	}
	if(fread(data, 1, BLOCK_SIZE, file) != BLOCK_SIZE) {
		printf("fread to few bytes\n");
		return -EIO;
	}
	return 0;
}

int io_write(addr_t addr, const char * data) {
	if(fseek(file, addr * BLOCK_SIZE, SEEK_SET)) {
		//Ok, extend file:
		fseek(file, 0, SEEK_END);
		int diff = addr - ftell(file);
		char * zeros = (char*) calloc(diff, 1);
		fwrite(zeros, 1, diff, file);
		free(zeros);
	}
	if(fwrite(data, 1, BLOCK_SIZE, file) != BLOCK_SIZE) {
		printf("fwrite to few bytes\n");
		return -EIO;
	}
	return 0;
}

