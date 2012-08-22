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

struct file_entry_t {
	addr_t len;		//length of name, including terminating NULL, 0 == END
	addr_t address;
	addr_t parent_inode;
	char * name;
};

#define INODE_BLOCKS ( ( BLOCK_SIZE - sizeof(addr_t) - sizeof(struct stat)) / sizeof(addr_t) )

struct inode_t {
	struct stat attributes;
	addr_t block_addr[INODE_BLOCKS];
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

void write_data(addr_t address, const char* data, size_t size);

addr_t next_free_block(const addr_t prev, fbl_pos_t * fbl_pos);
void mark_block_from_pos(const fbl_pos_t * fbl_pos, char bit);
void mark_block(const addr_t addr, char bit);

file_entry_t * find_entry(const char * path);

inode_t read_inode(addr_t addr);
void write_inode(inode_t * inode);
void delete_inode(inode_t * inode);
inode_t create_inode(inode * in_dir, const char* name, mode_t mode);

void read_inode_data(const inode_t * inode, size_t offset, size_t size, char * data);
int write_inode_data(const inode_t * inode, size_t offset, size_t size, const char * data);

int is_directory(const inode_t * inode);
//Addresses are relative, addr is updated to point to next file entry afterwards, returns NULL on eol
file_entry_t * next_file_entry(const inode * inode, addr_t * addr);
void free_file_entry(file_entry_t * entry);

addr_t allocate_block();
addr_t allocate_block_cont(addr_t prev); //Start at given addr
void delete_block(addr_t addr); //remember to check if fbl == 0

//Called on new systems to create initial structure
void format();


#endif
