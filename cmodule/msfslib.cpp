#include "msfslib.h"
#include "io.h"

#include <cstdio>
#include <cstdlib>
#include <stddef.h>
#include <map>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <string>
#include <assert.h>
#include <time.h>

static std::map<const char *, addr_t> files;

static struct cache_entry {
	addr_t addr;
	char data[BLOCK_SIZE];
	int valid;
}

#define CACHE_SIZE 10

cache_entry block_cache[CACHE_SIZE];

static int next_cache_entry_fill = 0;

static addr_t * fbl_addr;
static int num_fbls, num_alloc_fbls; //Actual number, allocated in local list, num_alloc >= num_fbls

static char active_fbl[BLOCK_SIZE];
static int active_fbl_index;

// Split path into parts
static char ** split_path( const char * path);
// Free path created by split_path
static void free_path(char ** path);

static file_entry_t * find_entry_internal_path(const char ** path, addr_t node);
static file_entry_t * find_entry_in_dir(const char * name, const inode_t * inode);

static void read_fbl_addresses();
static void fill_fbl_addr();
static char* get_fbl(int index);

/*
 * An internal adress in an inode
 */
static struct inode_addr_t {
	unsigned int block_index;
	addr_t block_addr;
	addr_t addr_in_block;
}

//Addr is relative start of data in inode
static inode_addr_t find_addr_in_inode(const inode * inode, size_t addr);

static char** split_path(char * path);

static char * zeroes; //BLOCK_SIZE of zeros
static char * block; //Always block_size big. Used for sending data that is less than BLOCK_SIZE

static cache_entry * find_or_create_cache_entry(addr_t address) {
	for(int i = 0; i< CACHE_SIZE; ++i) {
		if(address == block_cache[i].addr) {
			return block_cache + i;
		}
	}
	cache_entry * entry = block_cache[next_cache_entry_fill++];
	entry->addr = address;
	entry->valid = 0;
	next_cache_entry_fill = next_cache_entry_fill % 10;

	return entry;
}

void init() {

	zeroes = (char*) calloc(BLOCK_SIZE, 1);
	block = (char*) calloc(BLOCK_SIZE, 1);

	cache_entry empty;
	empty.valid = 0;
	for(int i = 0; i< CACHE_SIZE; ++i) {
		block_cache[i] = empty;
	}

	fbl_addr = (addr_t*) malloc( sizeof(addr_t) * 5 );
	num_alloc_fbls = 5;
	num_fbls = 1;
	//Set first fbl addr:
	fbl_addr[0] = ROOT_FBL;
	
	fill_fbl_addr();
}

void cleanup() {
	free(zeroes);
	free(block);
	free(fbl_addr);
}

void read_block(addr_t address, char * data) {
	cache_entry * cache = find_or_create_cache_entry(address);
	if(cache->valid == 0 && io_read(address, cache->data)) { //Only read if cache entry was invalid
		msfs_error = -EIO;
		return;
	}

	memcpy(data, cache->data, BLOCK_SIZE);
	cache->valid = 1;
}

void write_block(addr_t address, const char * data) {
	cache_entry * cache = find_or_create_cache_entry(address);
	memcpy(cache->data, data, BLOCK_SIZE);
	cache->valid = 1;
	if(io_write(address, data)) {
		msfs_error = -EIO;
	}
}

void write_data(addr_t address, const char* data, size_t size) {
	assert(size <= BLOCK_SIZE);
	if(size == BLOCK_SIZE) {
		write_block(address, data);
	} else {
		memcpy(block, data, size);
		write_block(address, block);
	}
}

addr_t allocate_block() {
	return allocate_block_cont(DATA_START);
}

addr_t allocate_block_cont(addr_t prev) {
	fbl_pos_t fbl_pos;
	addr_t addr = next_free_block(prev, &fbl_pos);
	//Write zeroes to the block:
	write_block(addr, zeroes);
	//Mark block in use
	mark_block_from_pos(&fbl_pos, 1);
	return addr;
}

static char** split_path(char * path) {
	int num_parts = 1;
	char * found;

	found = strchr(path+1, '/');
	while(found != NULL) {
		++num_parts;
		found = strchr(found + 1, '/');
	}
	++num_parts;


	char ** parts = (char**) malloc(sizeof(char*) * num_parts);
	int index = 0;
	found = strtok(path + 1, "/");
	while(found != NULL) {
		parts[index++] = found;
		found = strtok(NULL, "/");
	}
	parts[num_parts - 1] = NULL;

	return parts;
}

file_entry_t * find_entry(const char * in_path) {
	std::map<const char*, addr_t>::iterator it = files.find(in_path);
	if(it != files.end()) return it->second;

	assert(in_path[0] == '/');

	char path[strlen(in_path)-1];
	strcpy(path, in_path+1);

	char ** parts = split_path(path);

	file_entry_t * entry= find_entry_internal_path((const char**) parts, ROOT_NODE);

	free(parts);

	if(addr != 0) {
		files[in_path] = addr;
	}
	return addr;
}

static file_entry_t * find_entry_in_dir(const char * name, const inode_t * inode) {
	addr_t cur_addr = 0;
	file_entry_t * entry;
	for(entry = next_file(inode, &cur_addr); entry != NULL; entry = next_file(inode, &cur_addr)) {
		if(strcmp(name, entry->name) == 0) {
			return entry;
		}
		free_file_entry(entry);
	}
}

file_entry_t * next_file_entry(const inode * inode, addr_t * addr) {
	file_entry_t * entry = (file_entry_t*) malloc(sizeof(file_entry_t));
	read_inode_data(inode, *addr, (sizeof(addr_t) * 2), entry);
	if(entry->len == 0) {
		free(entry);
		return NULL;
	} else {
		entry->name = (char*) malloc(entry->len);
		*addr += sizeof(addr_t) *2;
		read_inode_data(inode, *addr, entry->len , entry->name);
		*addr += entry->len;
		entry->parent = inode->attributes.st_ino;
		return entry;
	}
}

void free_file_entry(file_entry_t * entry) {
	free(entry->name);
	free(entry);
}

/*
addr_t find_entry_internal_path(const char ** path, addr_t node_addr) {
	directory_entry_t * dir = get_directory(node_addr);
	for(file_entry_t * cur_file = dir->file_list; cur_file != NULL; cur_file = cur_file->next) {
		if(strcmp(path[0], cur_file->name) == 0) {
			free_directory(dir);
			if(path[1] == NULL)
				return cur_file->address;
			else
				return find_entry_internal_path(path+1, cur_file->address);
		}
	}
	printf("File entry not found: %s (in directory %lu) \n", path[0], dir->attributes.st_ino);
	free_directory(dir);
	return 0;
}
*/

//Addr is relative start of data in inode
static inode_addr_t find_addr_in_inode(const inode_t * inode, size_t addr) {

	inode_addr_t ret;
	ret.block_index = floor(addr/BLOCK_SIZE);
	unsigned int inode_index = ret.block_index / INODE_BLOCKS;
	inode_t * block_node = inode;
	for(; inode_index > 0; --inode_index) {
		if(block_node->next_block == 0) {
			msfs_error = -EFAULT;
			printf("Error: Trying to find address in inode, outside inode's address space (address: %d, block index: %d)\n", addr, ret.block_index);
			return ret;
		}
		read_block(block_node->next_block, block_cache);
		block_node = (inode_t*) block_cache;
	}

	ret.block_addr = block_node.block_addr[ret.block_index];
	ret.addr_in_block = (addr % BLOCK_SIZE);
	
	return ret;
}

inode_t read_inode(addr_t addr) {
	read_block(addr, block);
	inode_t inode;
	memcpy(&inode, block, sizeof(inode_t));
	return inode;
}

void write_inode(inode_t * inode) {
	write_data((addr_t) inode->attibutes.st_ino, (const char*)inode, sizeof(inode_t));
}

void delete_inode(inode_t * inode) {
	//find parent directory:
}


inode_t create_inode(inode * in_dir, const char* name, mode_t mode) {
	inode_t inode;
	if(!is_directory(in_dir)) {
		msfs_error = -ENOTDIR;
		return inode;
	}
	//First check if file exists in directory
	file_entry_t * entry = find_entry_in_dir(name, in_dir);
	if(entry != NULL) {
		free_file_entry(entry);
		msfs_error = -EEXIST;
		return inode;
	}

	inode.attibutes.st_ino = allocate_block();
	inode.next_block = 0;
	inode.attibutes.st_blocks = 1;
	inode.attibutes.st_atime = time();
	inode.attibutes.st_mtime = time();
	inode.attibutes.st_ctime = time();
	inode.attibutes.st_nlink = 0;
	inode.attibutes.st_size = 0;
	inode.attibutes.st_blksize = BLOCK_SIZE;
	inode.attibutes.st_mode = mode;

	write_inode(&inode);
}

char * read_inode_data(const inode_t * inode, size_t offset, size_t size, char * data) {
	
}

int write_inode_data(const inode_t * inode, size_t offset, size_t size, const char * data) {

}

int is_directory(const inode_t * inode) {
	return (inode->attibutes.st_mode & S_IFDIR);
}

directory_entry_t * get_directory(const addr_t addr) {
	int cur_block = 0;
	read_block(addr, block);
	directory_entry_t * dir = (directory_entry_t*) malloc(sizeof(directory_entry_t));
	dir->attributes = * ( (struct stat*) (block + offsetof(directory_entry_t, attributes)) );
	dir->parent_addr = * ( (addr_t*) (block + offsetof(directory_entry_t, parent_addr)) );
	dir->num_files = 0;
	dir->num_file_entries = 1;
	dir->blocks = (addr_t*) malloc(dir->attributes.st_blocks * sizeof(addr_t));
	dir->blocks[0] = addr;
	++cur_block;

	fs_file_entry_t * cur_file = (fs_file_entry_t*) (block + offsetof(directory_entry_t, file_list));
	if(cur_file->address == 0) {
		dir->file_list = NULL;
		return dir;
	}

	++dir->num_files;

	int name_len;
	int npos;

	file_entry_t * file = NULL;

	while(cur_file->address != 0) {
		++dir->num_file_entries;
		if(cur_file->address > 2) {
			//normal case, new file
			file_entry_t * next_file = (file_entry_t*) malloc(sizeof(file_entry_t));
			if(file != NULL) {
				file->next = next_file;
			} else {
				dir->file_list = next_file;
			}
			file = next_file;

			npos = 0;
			name_len = DIR_ENTRY_NAME_LEN;

			file->name = (char*) malloc(name_len);
			file->address = cur_file->address;

			++dir->num_files;

		} else if(cur_file->address == 2) {
			//Continue directory entry at address in name:
			addr_t *cont = (addr_t*) cur_file->name;
			read_block(*cont, block);
			dir->block[cur_block++] = *cont;
			cur_file = (fs_file_entry_t*) block;
			continue;
		}

		if(npos + DIR_ENTRY_NAME_LEN > name_len) {
			name_len *= 2;
			file->name = (char*) realloc(file->name, name_len);
		}
		memcpy(file->name + npos, cur_file->name, DIR_ENTRY_NAME_LEN);
		npos += DIR_ENTRY_NAME_LEN;
		++cur_file;

	}
	return dir;
}

void free_directory(directory_entry_t * dir) {
	for(file_entry_t * cur_file = dir->file_list; cur_file != NULL; ) {
		free(cur_file->name);
		file_entry_t * next_file = cur_file->next;
		free(cur_file);
		cur_file = next_file;
	}
	free(blocks);
	free(dir);
}

void write_directory(directory_entry_t * dir) {
	addr_t addr = dir->attributes.st_ino;
	int extra_blocks = dir->num_file_entries - FILE_ENTRIES_IN_FIRST_BLOCK;
	char * data = (char*) malloc(BLOCK_SIZE * (extra_blocks + 1) );

	memcpy(data, dir->attributes, sizeof(struct stat));
	memcpy(data, dir->parent_addr, sizeof(addr_t));

	int file_entries_left_in_block = FILE_ENTRIES_IN_FIRST_BLOCK;

	fs_file_entry_t fe;

	for( file_entry_t * f = dir->file_list; f != NULL; f = f->next ) {
		memcpy(data, 
	}

}

static void check_fbl_size(int index) {
	if(index >= num_alloc_fbls) {
		num_alloc_fbls *= 2;
		fbl_addr = (addr_t*) realloc(fbl_addr, num_alloc_fbls * sizeof(addr_t));
	}
}

static void fill_fbl_addr() {
	char * fbl = get_fbl(0);
	addr_t * next_addr = (addr_t*) fbl;
	int index = 1;

	while( *next_addr != 0 ){
		check_fbl_size(index);

		fbl_addr[index] = *next_addr;
		++num_fbls;
		fbl = get_fbl(index++);
		next_addr = (addr_t*) fbl;
	} 
}

static char* get_fbl(int index) {
	if(index == active_fbl_index) return active_fbl;

	read_block(fbl_addr[index], active_fbl);
	active_fbl_index = index;
	return active_fbl;
}

static inline char read_bit(char c, short pos) {
	return (c >> pos) & 1;
}

void mark_block_from_pos(const fbl_pos_t * fbl_pos, char bit) {
	check_fbl_size(fbl_pos->index);
	if(fbl_pos->index >= num_fbls) {
		char * fbl = get_fbl(num_fbls - 1);
		addr_t * next_addr = (addr_t*) fbl;

		addr_t addr = allocate_block();
		*next_addr = addr;
		fbl_addr[num_fbls] = addr;
		++num_fbls;
	}

	char * fbl = get_fbl(fbl_pos->index);
	char * c = fbl + (ADDR_SIZE + fbl_pos->char_index);
	if(read_bit(*c, fbl_pos->bit_pos) == bit) return;
	//We know the bit shall be flipped, and can just xor it with 1
	*c ^= 1 << fbl_pos->bit_pos; 
	//Write the block:
	write_block(fbl_addr[fbl_pos->index], fbl);
}

void mark_block(const addr_t addr, char bit) {
	fbl_pos_t pos;
	pos.index = addr / FREE_BLOCK_LIST_BLOCKS;
	addr_t internal_pos = addr % FREE_BLOCK_LIST_BLOCKS;
	pos.char_index = (int) floor(internal_pos / 8);
	pos.bit_pos = internal_pos % FREE_BLOCK_LIST_SIZE;

	mark_block_from_pos(&pos, bit);
}

addr_t next_free_block(const addr_t prev, fbl_pos_t * fbl_pos) {
	addr_t cur = prev + 1;
	int fbl_index = cur / FREE_BLOCK_LIST_BLOCKS;
	while(fbl_index < num_fbls) {
		addr_t internal_pos = cur % FREE_BLOCK_LIST_BLOCKS;
		short char_index = (int) floor(internal_pos / 8);
		short bit_pos = internal_pos % FREE_BLOCK_LIST_SIZE;
		if( read_bit( get_fbl(fbl_index)[ADDR_SIZE + char_index], bit_pos) == 0) {
			fbl_pos->index = fbl_index;
			fbl_pos->char_index = char_index;
			fbl_pos->bit_pos = bit_pos;
			return cur;
		}
		++cur;
		fbl_index = cur / FREE_BLOCK_LIST_BLOCKS;
	};
	//Fell through, return next block
	fbl_pos->index = fbl_index;
	fbl_pos->char_index = 0;
	fbl_pos->bit_pos = 0;
	
	return cur;
}

