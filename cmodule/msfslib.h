#ifndef MSFSLIB_H
#define MSFSLIB_H

#define FUSE_USE_VERSION 28
#include <fuse.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

#define BLOCK_SIZE 512

#define VERSION 0
#define HEADER_TEXT "minecraft-fs"

#define IN_BLOCK_SIZE(size) (size)/BLOCK_SIZE

#define MAX_BLOCKS UINT_MAX

#define SIGNATURE_BLOCK 0

#define ROOT_FBL 1

#define ROOT_NODE 2

#define DATA_START 2


typedef uint32_t addr_t;

#define ADDR_SIZE sizeof(addr_t)

extern int msfs_error;

/**
 * Header:
 * [ one signature block: HEADER_TEXT,(addr_t)VERSION, (addr_t)BLOCK_SIZE ]
 * [first list of free blocks]
 * [dir entry /]
 *
 * ---
 *
 * data
 */

/**
 * Free block list (fbl):
 * [address to next (or 0), ADDR_SIZE bytes ]
 * [ rest of it is bitmask for free blocks ]
 *
 * A fbl is a bitmask of which blocks inside a FREE_BLOCK_LIST_BLOCKS sized region that
 * are free.
 */

#define FREE_BLOCK_LIST_SIZE ( BLOCK_SIZE - ADDR_SIZE )
#define FREE_BLOCK_LIST_BLOCKS ( FREE_BLOCK_LIST_SIZE * 8 )

/*
 * Stored data only consist of len, address, name
 */
struct file_entry_t {
	addr_t len;		//length of name, including terminating NULL, 0 == END
	addr_t address;
	addr_t parent_inode;
	char * name;
	char * path;
};

#define INODE_BLOCKS ( ( BLOCK_SIZE - sizeof(addr_t) - sizeof(struct stat)) / sizeof(addr_t) )

struct inode_t {
	struct stat attributes;
	addr_t block_addr[INODE_BLOCKS]; /* List of addresses to the blocks of this inode */
	addr_t next_block; /* Address to the next block in this inode index */
};

/* Structure to store a position inside a fbl list */
struct fbl_pos_t {
	int index;
	short char_index;
	short bit_pos;
};

//Set verify to 0 to not verify signature block (for ex formating)
int init(const char * option, int verify);
void cleanup();

void reset_error();

/* Read and write single blocks (cached) */
void read_block(addr_t address, char* data);
void write_block(addr_t address, const char* data);

/*
 * Writes from offset to the end of the block that address resides in
 * Note that offset + size must be less or equal to BLOCK_SIZE
 */
void write_data(addr_t address, const char* data, size_t offset, size_t size);

addr_t next_free_block(const addr_t prev, fbl_pos_t * fbl_pos);

/* Set the value of a bit in a fbl from a fbl_pos */
void mark_block_from_pos(const fbl_pos_t * fbl_pos, char bit_value);

/* Set the value of a bit in a fbl from address. Returns the fbl_pos for the address*/
fbl_pos_t mark_block(const addr_t addr, char bit_value);

file_entry_t * find_entry(const char * path);
file_entry_t * clone_entry(const file_entry_t * entry);

inode_t inode_from_path(const char * path);

inode_t read_inode(addr_t addr);
void write_inode(inode_t * inode);
inode_t create_inode(inode_t * in_dir, const char* name, mode_t mode);
inode_t create_inode_from_path(const char * in_path, mode_t mode);

void delete_file_entry(file_entry_t * file); //This also frees the file_entry
void add_file_entry(file_entry_t * file, inode_t * dir);

/* returns number of read bytes */
int read_inode_data(inode_t * inode, size_t offset, size_t size, char * data);
int write_inode_data(inode_t * inode, size_t offset, size_t size, const char * data); //This one can change block count in inode

int is_directory(const inode_t * inode);
//Addresses are relative, addr is updated to point to next file entry afterwards, returns NULL on eol
file_entry_t * next_file_entry(inode_t * inode, addr_t * addr);
void free_file_entry(file_entry_t * entry);

int check_access(const inode_t * inode, int flags);

//Bumps atime and writes inode
void bump_atime(inode_t * inode);

unsigned int file_count(inode_t *inode);

addr_t allocate_block();
addr_t allocate_block_cont(addr_t prev); //Start at given addr
void delete_block(addr_t addr);

void rename_file(const char * from, const char * to);

/* Empty all caches */
void clear_cache();

//Called on new systems to create initial structure
void format();

void print_fbl();

#endif
