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

static std::map<const char *, addr_t> files;

static addr_t * fbl_addr;
static int num_fbls, num_alloc_fbls; //Actual number, allocated in local list, num_alloc >= num_fbls

static char active_fbl[BLOCK_SIZE];
static int active_fbl_index;

// Split path into parts
static char ** split_path( const char * path);
// Free path created by split_path
static void free_path(char ** path);

static addr_t find_entry_internal_path(const char ** path, addr_t node);

static void read_fbl_addresses();
static void fill_fbl_addr();
static char* get_fbl(int index);

static char** split_path(char * path);

static char * zeroes; //BLOCK_SIZE of zeros

void init() {
	zeroes = (char*) calloc(BLOCK_SIZE, 1);

	fbl_addr = (addr_t*) malloc( sizeof(addr_t) * 5 );
	num_alloc_fbls = 5;
	num_fbls = 1;
	//Set first fbl addr:
	fbl_addr[0] = ROOT_FBL;
	
	fill_fbl_addr();
}

void cleanup() {
	free(zeroes);
	free(fbl_addr);
}

void read_block(addr_t address, char * data) {
	if(io_read(address, data)) {
		msfs_error = -EIO;
	}
}

void write_block(addr_t address, const char * data) {
	if(io_write(address, data)) {
		msfs_error = -EIO;
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

addr_t find_entry(const char * in_path) {
	std::map<const char*, addr_t>::iterator it = files.find(in_path);
	if(it != files.end()) return it->second;

	assert(in_path[0] == '/');

	char path[strlen(in_path)-1];
	strcpy(path, in_path+1);

	char ** parts = split_path(path);

	addr_t addr = find_entry_internal_path((const char**) parts, ROOT_NODE);

	free(parts);

	if(addr != 0) {
		files[in_path] = addr;
	}
	return addr;
}

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

directory_entry_t * get_directory(const addr_t addr) {
	char block[BLOCK_SIZE];
	read_block(addr, block);
	directory_entry_t * dir = (directory_entry_t*) malloc(sizeof(directory_entry_t));
	dir->attributes = * ( (struct stat*) (block + offsetof(directory_entry_t, attributes)) );
	dir->parent_addr = * ( (addr_t*) (block + offsetof(directory_entry_t, parent_addr)) );

	fs_file_entry_t * cur_file = (fs_file_entry_t*) (block + offsetof(directory_entry_t, file_list));
	if(cur_file->address == 0) {
		dir->file_list = NULL;
		return dir;
	}

	int name_len;
	int npos;

	file_entry_t * file = NULL;

	while(cur_file->address != 0) {
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

		} else if(cur_file->address == 2) {
			//Continue directory entry at address in name:
			addr_t *cont = (addr_t*) cur_file->name;
			read_block(*cont, block);
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
	free(dir);
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


