#include "msfslib.h"

#include <ctype.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>

static void print_data(char * tmp_block, size_t size) {
	for(unsigned int i=0; i<size; ++i) {
		printf("%02x:%c ", (unsigned char) tmp_block[i]  , isprint(tmp_block[i]) ? tmp_block[i] : '-');
		if((i + 1) % 32 == 0) printf("\n");
		if((i + 1) % BLOCK_SIZE == 0) printf("\n");
	}
	printf("\n");
}

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

					inode_t dir_inode = read_inode(e->address);
					free_file_entry(e);

					addr_t addr = 0;
					file_entry_t * entry;

					if(is_directory(&dir_inode)) {
						entry = next_file_entry(&dir_inode, &addr);

						while(entry != NULL) {
							//printf("%s at address %u\n", entry->name, entry->address);

							free_file_entry(entry);
							entry = next_file_entry(&dir_inode, &addr);
						}
					}
				}
			} else if(strcmp(argv[1], "block") == 0) { //inspect block
				if(argc < 3) {
					printf("Missing argument: block\n");
					return -1;
				}
				char tmp_block[BLOCK_SIZE];
				read_block(atoi(argv[2]), tmp_block);
				if(msfs_error!=0) return msfs_error;

				print_data(tmp_block, BLOCK_SIZE);
			} else if(strncmp(argv[1], "ino", 3) == 0) { //inspect inode
				if(argc < 3) {
					printf("Missing argument: inode number\n");
					return -1;
				}
				inode_t inode = read_inode(atoi(argv[2]));
				printf("Inode %lu: size: %lu bytes, %lu blocks, directory: %d\n", inode.attributes.st_ino, inode.attributes.st_size, inode.attributes.st_blocks, is_directory(&inode));
				printf("Next inode: %u\n", inode.next_block);
				printf("Blocks: \n");
				for(unsigned int i=0; i<INODE_BLOCKS; ++i) {
					printf("%u ", inode.block_addr[i]);
					if( ( i + 1) % 10 == 0) printf("\n");
				}
				printf("\n");
				printf("Data\n");
				char * data = (char*)malloc(inode.attributes.st_size);
				int bytes = read_inode_data(&inode, 0, inode.attributes.st_size, data);
				print_data(data, bytes);
				free(data);
			} else if(strcmp(argv[1], "fbl") == 0) { //show fbl
				print_fbl();
			} else {
				printf("Unknown command %s\n", argv[1]);
			}
		} else {
			printf("msfs cli. Usage:\n"
					"format - format the file system\n"
					"ls [file]\n"
					"block [num]: Inspect block\n"
					"inode [num]: Inspect inode\n"
					"fbl: Show free block list\n");
		}
	}

	cleanup();
}
