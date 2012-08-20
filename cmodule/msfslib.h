#ifndef MSFSLIB_H
#define MSFSLIB_H

#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <limits.h>
#include <sys/stat.h>

#define BLOCK_SIZE 512

#define IN_BLOCK_SIZE(size) (size)/BLOCK_SIZE

#define MAX_BLOCKS UINT_MAX

#define ROOT_FBL 1

#define ROOT_NODE 2

#define DATA_START 2


typedef uint32_t addr_t;

#define ADDR_SIZE sizeof(addr_t)

int msfs_error = 0;

/**
 * Header:
 * [f][s][number (2 bytes)]
 * [first list of free blocks]
 * [dir entry /]
 * data
 */

/**
 * Free block list:
 * [4 byte addr to next (or 0) ]
 * [ rest of it is bitmask for free blocks]
 */

#define FREE_BLOCK_LIST_SIZE ( BLOCK_SIZE - ADDR_SIZE )
#define FREE_BLOCK_LIST_BLOCKS ( FREE_BLOCK_LIST_SIZE * 8 )

//Special for the file system
struct fs_file_entry_t {
	addr_t address;
	char name[12];
};

//Abstracted
struct file_entry_t {
	addr_t address;
	char * name;
};

struct directory_entry_t {
	struct stat attributes;
	addr_t parent_addr;
	file_entry_t * file_list;
};

struct inode_t {
	struct stat attributes;
	addr_t block_addr[10];
	addr_t next_block;
};

struct fbl_pos_t {
	int index;
	short char_index;
	short bit_pos;
};

void init();
void cleanup();

void read_block(addr_t address, char* data);
void write_block(addr_t address, const char* data);

addr_t next_free_block(const addr_t prev, fbl_pos_t * fbl_pos);
void mark_block_from_pos(const fbl_pos_t * fbl_pos, char bit);
void mark_block(const addr_t addr, char bit);

addr_t find_entry(const char * path);

directory_entry_t * get_directory(const addr_t addr);
void free_directory(directory_entry_t * dir);
void write_directory(directory_entry_t * dir);

inode_t read_inode(addr_t addr);
void write_inode(addr_t addr, const inode_t * inode);

char * read_file(const inode_t * inode, addr_t addr, addr_t size);
int write_file(const inode_t * inode, addr_t addr, addr_t size);
inode_t create_file(directory_entry_t * dir, const char* name, mode_t mode);
void delete_file(inode_t * inode);

void delete_block(addr_t addr); //remember to check if fbl == 0
addr_t allocate_block();
addr_t allocate_block_cont(addr_t prev); //Start at given addr

//Called on new systems to create initial structure
void format();


#endif
