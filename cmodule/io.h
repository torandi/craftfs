#ifndef IO_H
#define IO_H
#include "msfslib.h"

int init_io(const char * option);
int io_read(addr_t addr, char * data);

int io_write(addr_t addr, const char * data);

#endif
