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
#include <algorithm>

static std::map<const char *, file_entry_t*> files;

struct cache_entry {
	addr_t addr;
	char data[BLOCK_SIZE];
	int valid;
};

#define CACHE_SIZE 10

cache_entry block_cache[CACHE_SIZE];

static int next_cache_entry_fill = 0;

static addr_t * fbl_addr;
static int num_fbls, num_alloc_fbls; //Actual number, allocated in local list, num_alloc >= num_fbls

static char active_fbl[BLOCK_SIZE];
static int active_fbl_index;

static char** split_path(char * path);

static unsigned int file_count_abort(inode_t *inode, unsigned int abort_at);

static file_entry_t * find_entry_internal_path(const char ** path, addr_t node);
static file_entry_t * find_entry_in_dir(const char * name, inode_t * inode);

static void fill_fbl_addr();
static char* get_fbl(int index);

static inode_t create_blank_inode(mode_t mode);
static void delete_inode(inode_t * inode);

/*
 * An internal adress in an inode
 */
struct inode_addr_t {
	unsigned int block_index;
	addr_t block_addr;
	addr_t addr_in_block;
};

//Both these two may add blocks if the given index is outside the currently allocated blocks
static addr_t get_block_addr_from_inode(inode_t * inode, unsigned int block_index);
//Addr is relative start of data in inode
static inode_addr_t find_addr_in_inode(inode_t * inode, size_t addr);


static char * zeroes; //BLOCK_SIZE of zeros
static char * block; //Always block_size big. Used for sending data that is less than BLOCK_SIZE

static cache_entry * find_or_create_cache_entry(addr_t address) {
	for(int i = 0; i< CACHE_SIZE; ++i) {
		if(address == block_cache[i].addr) {
			return block_cache + i;
		}
	}
	cache_entry * entry = &(block_cache[next_cache_entry_fill++]);
	entry->addr = address;
	entry->valid = 0;
	next_cache_entry_fill = next_cache_entry_fill % 10;

	return entry;
}

void init(const char * option) {

	init_io(option);

	zeroes = (char*) calloc(BLOCK_SIZE, 1);
	block = (char*) calloc(BLOCK_SIZE, 1);

	file_entry_t tmp;
	tmp.len = 2;
	tmp.address = ROOT_NODE;
	tmp.parent_inode = 0;
	tmp.name = (char*)"/";
	tmp.path = (char*)"/";

	files["/"] = clone_entry(&tmp); //Always cache "/"

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
	if(msfs_error != 0) {
		printf("Not writing block, msfs_error is %d\n", msfs_error);
		return;
	}
	cache_entry * cache = find_or_create_cache_entry(address);
	memcpy(cache->data, data, BLOCK_SIZE);
	cache->valid = 1;
	if(io_write(address, data)) {
		msfs_error = -EIO;
	}
}

void write_data(addr_t address, const char* data, size_t offset, size_t size) {
	assert( (offset + size) <= BLOCK_SIZE);
	if(size == BLOCK_SIZE) {
		write_block(address, data);
	} else {
		read_block(address, block);
		memcpy(block+offset, data, size);
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

void delete_block(addr_t addr) {
	mark_block(addr, 0);
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
	std::map<const char*, file_entry_t*>::iterator it = files.find(in_path);
	if(it != files.end()) return it->second;

	assert(in_path[0] == '/');

	char path[strlen(in_path)-1];
	strcpy(path, in_path+1);

	char ** parts = split_path(path);

	file_entry_t * entry= find_entry_internal_path((const char**) parts, ROOT_NODE);

	strcpy(entry->path, in_path);

	free(parts);

	if(entry != NULL) {
		files[in_path] = clone_entry(entry);
	}
	return entry;
}

static file_entry_t * find_entry_in_dir(const char * name, inode_t * inode) {
	addr_t cur_addr = 0;
	file_entry_t * entry;
	for(entry = next_file_entry(inode, &cur_addr); entry != NULL; entry = next_file_entry(inode, &cur_addr)) {
		if(strcmp(name, entry->name) == 0) {
			return entry;
		}
		free_file_entry(entry);
	}
	return NULL;
}

file_entry_t * clone_entry(const file_entry_t * old_entry) {
	file_entry_t * new_entry = (file_entry_t*) malloc(sizeof(file_entry_t));
	memcpy(new_entry, old_entry, sizeof(file_entry_t));
	new_entry->name = (char*) malloc(new_entry->len);
	strcpy(new_entry->name, old_entry->name);
	if(old_entry->path != NULL) {
		new_entry->path = (char*) malloc(strlen(old_entry->path)+1);
		strcpy(new_entry->path, old_entry->path);
	}
	return new_entry;
}

file_entry_t * next_file_entry(inode_t * inode, addr_t * addr) {
	file_entry_t * entry = (file_entry_t*) malloc(sizeof(file_entry_t));
	read_inode_data(inode, *addr, (sizeof(addr_t) * 2), (char*)entry);
	if(entry->len == 0) {
		free(entry);
		return NULL;
	} else {
		entry->name = (char*) malloc(entry->len);
		*addr += sizeof(addr_t) *2;
		read_inode_data(inode, *addr, entry->len , entry->name);
		*addr += entry->len;
		entry->parent_inode = inode->attributes.st_ino;
		entry->path = NULL;
		return entry;
	}
}

void free_file_entry(file_entry_t * entry) {
	free(entry->name);
	free(entry);
}


file_entry_t * find_entry_internal_path(const char ** path, addr_t node_addr) {
	inode_t inode = read_inode(node_addr);
	if(!is_directory(&inode)) {
		msfs_error = -ENOTDIR;
		return NULL;
	}

	file_entry_t * entry = find_entry_in_dir(path[0], &inode);
	if(entry == NULL) {
		printf("File entry not found: %s (in directory %u) \n", path[0], node_addr);
		msfs_error = -ENOENT;
	} else if(path[1] == NULL) {
		//This was the last part of the path, return it:
		return entry;
	} else {
		//We need to go deeper!
		file_entry_t * next = find_entry_internal_path(path + 1, entry->address);
		free_file_entry(entry);
		return next;
	}
	abort(); //Should never get here
}


static addr_t get_block_addr_from_inode(inode_t * inode, unsigned int block_index) {
	unsigned int inode_index = block_index / INODE_BLOCKS;

	short inode_changed = 0;

	inode_t * block_node = inode;
	addr_t prev_last = 0;

	for(; inode_index > 0; --inode_index) {
		prev_last = block_node->block_addr[INODE_BLOCKS - 1];

		if(block_node->next_block == 0) {
			//Must add a block to this inode
			inode_t new_inode = create_blank_inode(inode->attributes.st_mode);
			block_node->next_block = new_inode.attributes.st_ino;
			++(inode->attributes.st_blocks);
			memcpy(block_cache, &new_inode, sizeof(inode_t));
			inode_changed = 1;
		} else {
			read_block(block_node->next_block, (char*)block_cache);
		}
		block_node = (inode_t*) block_cache;
	}


	addr_t addr = block_node->block_addr[block_index];
	if(addr == 0) {
		//Must allocate this block!
		addr_t prev = (block_index > 0) ? block_node->block_addr[block_index] : prev_last;
		addr = block_node->block_addr[block_index] = allocate_block_cont(prev);
		++(inode->attributes.st_blocks);
		inode_changed = 1;
		if(block_node != inode) {
			write_inode(block_node);
		}
	}

	if(inode_changed) write_inode(inode);

	return addr;
}

//Addr is relative start of data in inode
static inode_addr_t find_addr_in_inode(inode_t * inode, size_t addr) {

	inode_addr_t ret;
	ret.block_index = floor(addr/BLOCK_SIZE);

	ret.block_addr = get_block_addr_from_inode(inode, ret.block_index);
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
	write_data((addr_t) inode->attributes.st_ino, (const char*)inode, 0, sizeof(inode_t));
}

void delete_file_entry(file_entry_t * file_entry) {
	inode_t directory = read_inode(file_entry->parent_inode);
	inode_t file = read_inode(file_entry->address);
	
	if(!is_directory(&directory)) {
		msfs_error = -ENOTDIR;
		return;
	}

	if(is_directory(&file) && file_count_abort(&file, 1) > 0) {
		msfs_error = -ENOTEMPTY;
		return;
	}

	if(strcmp(file_entry->name, "/") == 0) {
		printf("Can not delete /\n");
		msfs_error = -EPERM;
		return;
	}

	if(strcmp(file_entry->name, "..") == 0) {
		printf("Can not delete ..\n");
		msfs_error = -EPERM;
		return;
	}

	//Remove from directory listing:
	
	char * data = (char*) malloc(directory.attributes.st_size);
	addr_t next = 0;

	file_entry_t * entry;

	while( 1 ) {
		read_inode_data(&directory, next, (sizeof(addr_t) * 2), data + next);
		entry = (file_entry_t*) (data + next);
		next += sizeof(addr_t) * 2;
		if(entry->len == 0) break;

		read_inode_data(&directory, next, entry->len, data + next);
		if(strncmp(data + next, file_entry->name, strlen(file_entry->name)) == 0) {
			next -= sizeof(addr_t) * 2; //don't include this
		} else {
			next += entry->len;
		}
	}
	directory.attributes.st_size = next;
	write_inode_data(&directory, 0, directory.attributes.st_size, data);
	write_inode(&directory);
	--file.attributes.st_nlink;
	if(is_directory(&file) || file.attributes.st_nlink == 0) {
		delete_inode(&file);
	} else {
		write_inode(&file);
	}

	if(file_entry->path != NULL) {
		files.erase(file_entry->path); //nuke cache
	}
}

void add_file_entry(file_entry_t * file, inode_t * dir) {
	size_t cur_size = dir->attributes.st_size;
	if(!is_directory(dir)) {
		msfs_error = -ENOTDIR;
		return;
	}

	write_inode_data(dir, cur_size - sizeof(addr_t) * 2, sizeof(addr_t)*2, (char*)file);
	write_inode_data(dir, cur_size, file->len , file->name);
	cur_size += file->len;
	dir->attributes.st_size = cur_size;
	dir->attributes.st_mtime = time(NULL);

	write_inode(dir);

	inode_t f_inode = read_inode(file->address);
	f_inode.attributes.st_nlink += 1;
	write_inode(&f_inode);
}

static inode_t create_blank_inode(mode_t mode) {
	inode_t inode;
	inode.attributes.st_ino = allocate_block();
	inode.next_block = 0;
	inode.attributes.st_blocks = 1;
	inode.attributes.st_atime = time(NULL);
	inode.attributes.st_mtime = time(NULL);
	inode.attributes.st_ctime = time(NULL);
	inode.attributes.st_nlink = 0;
	inode.attributes.st_size = 0;
	inode.attributes.st_blksize = BLOCK_SIZE;
	inode.attributes.st_mode = mode;

	for(unsigned int i=0; i< INODE_BLOCKS; ++i) {
		inode.block_addr[i] = 0;
	}

	write_inode(&inode);

	return inode;
}

inode_t create_inode(inode_t * in_dir, const char* name, mode_t mode) {
	inode_t inode;
	if(!is_directory(in_dir)) {
		msfs_error = -ENOTDIR;
		return inode;
	}
	//First check if file exists in directory
	file_entry_t * exists = find_entry_in_dir(name, in_dir);
	if(exists != NULL) {
		free_file_entry(exists);
		msfs_error = -EEXIST;
		return inode;
	}

	inode = create_blank_inode(mode);

	if(is_directory(&inode)) {
		inode.attributes.st_nlink = 1;
		write_inode(&inode);
		//Create parent link
		file_entry_t parent_entry;
		parent_entry.address = in_dir->attributes.st_ino;
		parent_entry.len = 3;
		parent_entry.name = (char*)"..";
		add_file_entry(&parent_entry, &inode);
	}
	file_entry_t file_entry;
	file_entry.address = inode.attributes.st_ino;
	file_entry.len = strlen(name) + 1;
	file_entry.name = (char*) malloc(file_entry.len);
	strcpy(file_entry.name,name);
	add_file_entry(&file_entry, in_dir);

	return inode;
}

static void delete_inode(inode_t * inode) {
	for(unsigned int i=0; i<INODE_BLOCKS; ++i) {
		if(inode->block_addr[i] != 0) {
			delete_block(inode->block_addr[i]);
		}
	}
	if(inode->next_block != 0) {
		inode_t next = read_inode(inode->next_block);
		delete_inode(&next);
	}
	delete_block(inode->attributes.st_ino);
}

int read_inode_data(inode_t * inode, size_t offset, size_t size, char * data) {
	if((unsigned int) (offset + size) > inode->attributes.st_size) {
		size = inode->attributes.st_size - offset;
	}

	if(size <= 0) {
		return 0;
	}

	inode_addr_t start_addr = find_addr_in_inode(inode, offset);
	inode_addr_t end_addr = find_addr_in_inode(inode, offset + size);
	
	size_t data_offset = std::min( size , (size_t)( BLOCK_SIZE - start_addr.addr_in_block)); //Also size of first block for now

	if(data_offset == BLOCK_SIZE) {
		//Read whole block:
		read_block(start_addr.block_addr, data);
	} else {
		//read whole block to intermediate cache
		read_block(start_addr.block_addr, block);
		//And then memcpy
		memcpy(data, block + start_addr.addr_in_block, data_offset);
	}

	for(unsigned int block_index = start_addr.block_index + 1; block_index < end_addr.block_index; ++block_index) { //Iterate the intermediate blocks
		addr_t block_addr = get_block_addr_from_inode(inode, block_index);
		if(msfs_error != 0) return 0;
		read_block(block_addr, data + data_offset);
		data_offset += BLOCK_SIZE;
	}

	if(end_addr.addr_in_block != 0) { //If 0 the last block is not needed
		//read whole block to intermediate cache
		read_block(end_addr.block_addr, block);
		//And then memcpy
		memcpy(data + data_offset, block, end_addr.addr_in_block);
	}
	inode->attributes.st_atime = time(NULL);
	write_inode(inode);

	return size;
}

int write_inode_data(inode_t * inode, size_t offset, size_t size, const char * data) {
	inode_addr_t start_addr = find_addr_in_inode(inode, offset);
	inode_addr_t end_addr = find_addr_in_inode(inode, offset + size);
	
	size_t data_offset = std::min( size , (size_t) ( BLOCK_SIZE - start_addr.addr_in_block)); //Also size of first block for now

	write_data(start_addr.block_addr, data, start_addr.addr_in_block, data_offset );

	for(unsigned int block_index = start_addr.block_index + 1; block_index < end_addr.block_index; ++block_index) { //Iterate the intermediate blocks
		addr_t block_addr = get_block_addr_from_inode(inode, block_index);
		if(msfs_error != 0) return 0;
		write_block(block_addr, data + data_offset);
		data_offset += BLOCK_SIZE;
	}

	write_data(end_addr.block_addr, data + data_offset, 0, end_addr.addr_in_block);

	if((size_t) (offset + size) > inode->attributes.st_size) {
		inode->attributes.st_size = offset + size;
	}
	inode->attributes.st_atime = time(NULL);
	inode->attributes.st_mtime = time(NULL);
	write_inode(inode);

	return size;
}

int is_directory(const inode_t * inode) {
	return (inode->attributes.st_mode & S_IFDIR);
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

fbl_pos_t mark_block(const addr_t addr, char bit) {
	fbl_pos_t pos;
	pos.index = addr / FREE_BLOCK_LIST_BLOCKS;
	addr_t internal_pos = addr % FREE_BLOCK_LIST_BLOCKS;
	pos.char_index = (int) floor(internal_pos / 8);
	pos.bit_pos = internal_pos % FREE_BLOCK_LIST_SIZE;

	mark_block_from_pos(&pos, bit);

	return pos;
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

unsigned int file_count(inode_t *inode) {
	return file_count_abort(inode, 0);
}

static unsigned int file_count_abort(inode_t *inode, unsigned int abort_at) {
	unsigned int count = 0;
	int loop = 1;
	file_entry_t entry;
	addr_t addr = 0;
	while(loop) {
		read_inode_data(inode, addr, (sizeof(addr_t) * 2), (char*)&entry);
		if(entry.len == 0) {
			loop = 0;
		} else {
			addr += (sizeof(addr_t) * 2) + entry.len;
			++count;

			if(abort_at > 0 && (count - 1) >= abort_at) return abort_at;
		}
	}
	return (count - 1); // -1 to remove ..
}
