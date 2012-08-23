#include "msfslib.h"

#include <cstring>
#include <cstdio>

int main(int argc, const char ** argv) {
	if(argc > 1 && strcmp(argv[1], "format") == 0) {
		int err = init("minecraft.dev", 0);
		if(err != 0) {
			perror("Fail");
			return err;
		}
		format();
	} else {
		int err = init("minecraft.dev", 1);
		if(err != 0) return err;

		if(argc > 1) {
			if(strcmp(argv[1], "ls") == 0) {
				if(argc < 3) {
					printf("Missing argument: path\n");
					return -1;
				}
				file_entry_t * e = find_entry(argv[2]);
				if(e == NULL) {
					printf("File not found\n");
					return msfs_error;
				} else {
					printf("File found, address: %x\n", e->address);
					free_file_entry(e);
				}
			}
		} else {
			print_fbl();
		}
	}

	cleanup();
}
