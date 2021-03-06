#include "msfslib.h"
#include "io.h"
#include "timer.h"

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
#include <vector>

int msfs_error = 0;

static std::map<std::string, file_entry_t*> files;

typedef std::map<std::string, file_entry_t*>::iterator file_cache_it_t;

struct cache_entry {
	addr_t addr;
	char data[BLOCK_SIZE];
	int valid;
};

/* Cache of addresses to the inode blocks for a inode
 * That is, a cache of the linked list of inode blocks
 */
struct inode_cache_entry_t {
	addr_t addr;
	std::vector<addr_t> blocks;
	int valid;
};

#define CACHE_SIZE 10
#define INODE_INDEX_CACHE_SIZE 5

#define DISABLE_FILE_ENTRY_CACHE 0

cache_entry block_cache[CACHE_SIZE];
inode_cache_entry_t inode_index_cache[INODE_INDEX_CACHE_SIZE];

static int next_cache_entry_fill = 0;
static int next_inode_cache_entry_fill = 0;

/* Lookup list for fbl index to the address of that fbl */
static addr_t * fbl_addr;
/* Actual number & allocated in local list, num_alloc >= num_fbls */
static int num_fbls, num_alloc_fbls;

static int split_path(char * path, char*** parts);

static unsigned int file_count_abort(inode_t *inode, unsigned int abort_at);

static file_entry_t * find_entry_internal_path(const char ** path, int index, addr_t node);
static file_entry_t * find_entry_in_dir(const char * name, inode_t * inode);
static file_entry_t * find_entry_in_cache(const char ** path, int num_parts);

static void fill_fbl_addr();
static char* get_fbl(int index);

static inode_t create_blank_inode(mode_t mode);
static void delete_inode(inode_t * inode);
static char * join_path(const char **split_path, int num_parts);

static void clear_file_cache();

/* Remove the given file entry from the directory
 * Uncaches the entry, and everything down in the tree if recurse is true
 */
static void unlist_file_entry(file_entry_t * file_entry, inode_t * directory, int recursive);

/*
 * An internal address in an inode
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

//Copies path (must be free'd). removes trailing slash
static char * copy_and_trim_path(const char * path);

static char * zeroes; //BLOCK_SIZE of zeros
static char * block; //Always block_size big. Used for sending data that is less than BLOCK_SIZE

static char * blank_string;

static cache_entry * find_block_cache_entry(addr_t address) {
	for(int i = 0; i< CACHE_SIZE; ++i) {
		if(address == block_cache[i].addr) {
			return block_cache + i;
		}
	}
	return NULL;
}

static cache_entry * find_or_create_cache_entry(addr_t address) {
	cache_entry * entry = find_block_cache_entry(address);
	if(entry != NULL) return entry;

	entry = &(block_cache[next_cache_entry_fill]);
	entry->addr = address;
	entry->valid = 0;
	next_cache_entry_fill = ( next_cache_entry_fill + 1 ) % 10;

	return entry;
}

static std::vector<addr_t> * get_inode_index_cache(const inode_t * inode) {
	for(int i = 0; i< INODE_INDEX_CACHE_SIZE; ++i) {
		if((addr_t)inode->attributes.st_ino == inode_index_cache[i].addr) {
			inode_cache_entry_t * entry = &(inode_index_cache[i]);
			if(entry->valid == 0) {
					entry->blocks = std::vector<addr_t>();
					entry->blocks.push_back((addr_t)inode->attributes.st_ino);
					entry->valid = 1;
			}
			return &(entry->blocks);
		}
	}
	inode_cache_entry_t * entry = &(inode_index_cache[next_inode_cache_entry_fill]);
	entry->addr = (addr_t) inode->attributes.st_ino;
	entry->valid = 1;
	entry->blocks = std::vector<addr_t>();
	entry->blocks.push_back((addr_t)inode->attributes.st_ino);
	next_inode_cache_entry_fill = ( next_cache_entry_fill + 1 ) % 10;

	return &(entry->blocks);
}

static void uncache_inode(const inode_t * inode) {
	for(int i = 0; i< INODE_INDEX_CACHE_SIZE; ++i) {
		if((addr_t)inode->attributes.st_ino== inode_index_cache[i].addr) {
			inode_index_cache[i].valid = 0;
		}
	}
}

int init(const char * option, int verify) {
	int err;
	err = init_io(option);
	if( err != 0) {
		printf("Failed to initialize io\n");
		return err;
	}

	zeroes = (char*) calloc(BLOCK_SIZE, 1);
	block = (char*) calloc(BLOCK_SIZE, 1);
	blank_string = (char*) calloc(1, 1);

	if(verify != 0) {
		//Read signature block (and verify)
		read_block(SIGNATURE_BLOCK, block);
		if(strncmp(block, HEADER_TEXT, strlen(HEADER_TEXT)) != 0) {
			printf("Invalid file system (incorrect signature block).\n");
			return -EIO;
		}
		char * cur = block + strlen(HEADER_TEXT) + 1;
		addr_t * read_addr = (addr_t*) cur;
		if(*read_addr != VERSION) {
			printf("Invalid version of file system. (We are running version %d and system is %d\n", VERSION, *read_addr);
			return -EIO;
		}
		cur += sizeof(addr_t);
		read_addr = (addr_t*) cur;
		if(*read_addr != BLOCK_SIZE) {
			printf("Block size differ. Current block size: %d and system block size is %d\n", BLOCK_SIZE, *read_addr);
			return -EIO;
		}
	}

	file_entry_t tmp;
	tmp.len = 2;
	tmp.address = ROOT_NODE;
	tmp.parent_inode = 0;
	tmp.name = (char*)"/";
	tmp.path = (char*)"/";

	files["/"] = clone_entry(&tmp); //Always cache "/"

	cache_entry empty;
	empty.valid = 0;
	empty.addr = 0;
	for(int i = 0; i< CACHE_SIZE; ++i) {
		block_cache[i] = empty;
	}
	inode_cache_entry_t i_empty;
	i_empty.valid = 0;
	i_empty.addr = 0;
	for(int i = 0; i< INODE_INDEX_CACHE_SIZE; ++i) {
		inode_index_cache[i] = i_empty;
	}

	fbl_addr = (addr_t*) malloc( sizeof(addr_t) * 5 );
	num_alloc_fbls = 5;
	num_fbls = 1;
	//Set first fbl addr:
	fbl_addr[0] = ROOT_FBL;

	if(verify != 0) {
		fill_fbl_addr();
	}

	return msfs_error;
}

void cleanup() {
	for(file_cache_it_t it = files.begin(); it != files.end(); ++it) {
		free_file_entry(it->second);
	}
	free(zeroes);
	free(block);
	free(blank_string);
	free(fbl_addr);
}

/* Read single block (cached) */
void read_block(addr_t address, char * data) {
	cache_entry * cache = find_or_create_cache_entry(address);

	if(cache->valid == 0 && io_read(address, cache->data)) { //Only read if cache entry was invalid
		msfs_error = -EIO;
		return;
	}

	memcpy(data, cache->data, BLOCK_SIZE);
	cache->valid = 1;
}

/* Write single block */
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

/*
 * Writes from offset to the end of the block that address resides in
 * Note that offset + size must be less or equal to BLOCK_SIZE
 */
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

/* Find and allocate a free block (starting from the begining) */
addr_t allocate_block() {
	return allocate_block_cont(DATA_START);
}

/* Find and allocate a free block, starting from a previous position */
addr_t allocate_block_cont(addr_t prev) {
	fbl_pos_t fbl_pos;
	addr_t addr = next_free_block(prev, &fbl_pos);
	if(addr < DATA_START + 1) {
		printf("Critical error: allocated block with addr < DATA_START + 1\n");
		abort();
	}
	//Write zeroes to the block:
	write_block(addr, zeroes);
	//Mark block in use
	mark_block_from_pos(&fbl_pos, 1);
	return addr;
}

void delete_block(addr_t addr) {
	cache_entry * entry = find_block_cache_entry(addr);
	if(entry != NULL) entry->valid = 0;
	mark_block(addr, 0);
}

static int split_path(char * path, char*** parts) {
	int num_parts = 1;
	char * found;
	found = strchr(path, '/');
	while(found != NULL) {
		++num_parts;
		found = strchr(found + 1, '/');
	}

	*parts = (char**) malloc(sizeof(char*) * num_parts);
	int index = 0;
	found = strtok(path, "/");
	while(found != NULL) {
		(*parts)[index++] = found;
		found = strtok(NULL, "/");
	}
	for(int i=index; i<num_parts; ++i) {
		(*parts)[i] = blank_string;
	}

	return num_parts;
}

static char * join_path(const char ** split_path, int num_parts) {
	char * path = (char*)malloc(2);
	path[0] = '/';
	path[1] = 0;

	size_t curpos = 0;
	for(int i=0; i<num_parts; ++i) {

		path = (char*)realloc(path, strlen(path) + strlen(split_path[i]) + 2);
		path[curpos] = '/';
		memcpy(path + curpos + 1, split_path[i], strlen(split_path[i]) + 1 );

		curpos = strlen(path);
	}
	return path;
}


inode_t inode_from_path(const char * path) {
	inode_t inode;
	file_entry_t * entry = find_entry(path);
	if(entry == NULL) {
		assert(msfs_error != 0);
		return inode;
	}
	inode = read_inode(entry->address);
	free_file_entry(entry);
	return inode;
}

file_entry_t * find_entry(const char * in_path) {
	assert(in_path[0] == '/');

	printf("Find entry %s\n", in_path);

	char * path = copy_and_trim_path(in_path);

	char ** parts = NULL;
	int num_parts = split_path(path + 1, &parts);

	file_entry_t * entry = find_entry_in_cache((const char**) parts, num_parts);

	free(parts);

	free(path);

	return entry;
}

static file_entry_t * find_entry_in_dir(const char * name, inode_t * inode) {
	printf("find_entry_in_dir(name: %s,inode: %lu)\n", name, inode->attributes.st_ino);
	addr_t cur_addr = 0;
	file_entry_t * entry = next_file_entry(inode, &cur_addr);
	while(entry!=NULL) {
		if(strcmp(name, entry->name) == 0) {
			return entry;
		}
		free_file_entry(entry);

		entry = next_file_entry(inode, &cur_addr);
	}
	return NULL;
}

file_entry_t * clone_entry(const file_entry_t * old_entry) {
	if(old_entry == NULL) return NULL;

	file_entry_t * new_entry = (file_entry_t*) malloc(sizeof(file_entry_t));

	memcpy(new_entry, old_entry, sizeof(file_entry_t));

	new_entry->name = strdup(new_entry->name);

	if(old_entry->path != NULL) new_entry->path = strdup(old_entry->path);

	return new_entry;
}

file_entry_t * next_file_entry(inode_t * inode, addr_t * addr) {
	file_entry_t * entry = (file_entry_t*) malloc(sizeof(file_entry_t));
	read_inode_data(inode, *addr, (sizeof(addr_t) * 2), (char*)entry);
	if(entry->len == 0) {
		printf("Entry (NULL) : { %d, %d }\n", entry->len, entry->address);
		free(entry);
		return NULL;
	} else {
		entry->name = (char*) malloc(entry->len);
		*addr += sizeof(addr_t) *2;
		read_inode_data(inode, *addr, entry->len , entry->name);
		*addr += entry->len;
		entry->parent_inode = inode->attributes.st_ino;
		entry->path = NULL;
		printf("Entry: { len: %d, address: %d, name: %s }\n", entry->len, entry->address, entry->name);
		return entry;
	}
}

void free_file_entry(file_entry_t * entry) {
	free(entry->name);
	free(entry->path);
	free(entry);
}


file_entry_t * find_entry_internal_path(const char ** path, int index, addr_t node_addr) {
	inode_t inode = read_inode(node_addr);
	if(!is_directory(&inode)) {
		msfs_error = -ENOTDIR;
		return NULL;
	}

	//printf("Find entry (internal path): %s\n", path[index]);

	file_entry_t * entry = find_entry_in_dir(path[index], &inode);
	if(entry == NULL) {
		msfs_error = -ENOENT;
		return NULL;
	} else {
		assert(entry->path == NULL);
		entry->path = join_path(path, index+1);
		files[std::string(entry->path)] = clone_entry(entry);

		return entry;
	}
}

/*
 * Tries to find a entry in the cache matching num_parts of path
 */
static file_entry_t * find_entry_in_cache(const char ** path, int num_parts) {
	char * cache_path = join_path(path, num_parts);

	//printf("Searching for %s in cache (%d parts)\n", cache_path, num_parts);
	file_cache_it_t it = files.find(std::string(cache_path));

	free(cache_path);

	if(it != files.end()) {
		//printf("Cache hit! (%s: %u)\n", it->first.c_str(), it->second->address);
		return clone_entry(it->second);
	} else if(num_parts > 0) {
		file_entry_t * parent = find_entry_in_cache(path, num_parts - 1);

		if(parent != NULL) {
			file_entry_t * entry = find_entry_internal_path(path, num_parts - 1, parent->address);
			free_file_entry(parent);

			return entry;
		} else {
			return NULL;
		}

	} else {
		printf("Critical error, file entry cache corrupted (missing /)\n");
		abort();
	}
}

static addr_t get_block_addr_from_inode(inode_t * inode, unsigned int block_index) {
	unsigned int inode_index = block_index / INODE_BLOCKS;
	unsigned int relative_block_index = block_index % INODE_BLOCKS;

	short inode_changed = 0;

	char tmp_block[BLOCK_SIZE];

	inode_t * block_node = inode;

	addr_t prev_last = DATA_START;

	if(inode_index > 0) {
		std::vector<addr_t> * cache = get_inode_index_cache(inode);
		if(inode_index < cache->size()) {
			read_block((*cache)[inode_index], tmp_block);
			block_node = (inode_t*) tmp_block;
		} else {
			read_block(cache->back(), tmp_block);
			block_node = (inode_t*) tmp_block;

			for(unsigned int i = cache->size() - 1; i < inode_index; ++i) {
				prev_last = block_node->block_addr[INODE_BLOCKS - 1];
				if(block_node->next_block == 0) {
					//Must add a block to this inode
					inode_t new_inode = create_blank_inode(inode->attributes.st_mode);
					block_node->next_block = new_inode.attributes.st_ino;
					++(inode->attributes.st_blocks);
					memcpy(tmp_block, &new_inode, sizeof(inode_t));
					inode_changed = 1;
				} else {
					read_block(block_node->next_block, tmp_block);
				}
				block_node = (inode_t*) tmp_block;
				(*cache).push_back((addr_t) block_node->attributes.st_ino);
			}
		}
	}


	addr_t addr = block_node->block_addr[relative_block_index];

	if(addr == 0) {
		//Must allocate this block!
		addr_t prev = (relative_block_index > 0) ? block_node->block_addr[relative_block_index - 1] : prev_last;
		addr = block_node->block_addr[relative_block_index] = allocate_block_cont(prev);
		++(inode->attributes.st_blocks);
		inode_changed = 1;
		if(block_node != inode) {
			++(block_node->attributes.st_blocks);
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

	if(is_directory(&file) && file_count_abort(&file, 3) > 2) { // ignore . and ..
		msfs_error = -ENOTEMPTY;
		return;
	}

	if(strcmp(file_entry->name, "/") == 0) {
		printf("Can not delete /\n");
		msfs_error = -EPERM;
		return;
	}

	if(strcmp(file_entry->name, ".") == 0) {
		printf("Can not delete .\n");
		msfs_error = -EPERM;
		return;
	}

	if(strcmp(file_entry->name, "..") == 0) {
		printf("Can not delete ..\n");
		msfs_error = -EPERM;
		return;
	}

	//Remove from directory listing:
	unlist_file_entry(file_entry, &directory, 0);

	--file.attributes.st_nlink;
	if(( is_directory(&file) && file.attributes.st_nlink < 3) || file.attributes.st_nlink == 0) {
		printf("Deleting inode for file %s\n", file_entry->name);
		delete_inode(&file);
	} else {
		printf("Keeping inode for file %s (still got %lu links)\n", file_entry->name, file.attributes.st_nlink);
		write_inode(&file);
	}
}

static void unlist_file_entry(file_entry_t * file_entry, inode_t * directory, int recursive) {
	printf("Removing file entry %s from inode %lu\n", file_entry->path, directory->attributes.st_ino);

	char * data = (char*) malloc(directory->attributes.st_size);
	addr_t next_read = 0;
	addr_t next_write = 0;

	file_entry_t * entry;

	while( 1 ) {
		read_inode_data(directory, next_read, (sizeof(addr_t) * 2), data + next_write);
		entry = (file_entry_t*) (data + next_write);
		next_write += sizeof(addr_t) * 2;
		next_read += sizeof(addr_t) * 2;
		if(entry->len == 0) break;

		read_inode_data(directory, next_read, entry->len, data + next_write);
		next_read += entry->len;
		if(strncmp(data + next_write, file_entry->name, strlen(file_entry->name)) == 0) {
			next_write -= sizeof(addr_t) * 2; //don't include this
		} else {
			next_write += entry->len;
		}
	}

	directory->attributes.st_size = next_write;

	write_inode_data(directory, 0, directory->attributes.st_size, data);
	write_inode(directory);
	free(data);

	clear_file_cache();
}

void rename_file(const char * from_path, const char * in_to_path) {
	file_entry_t *  from_entry = find_entry(from_path);
	inode_t from_dir, to_dir;
	inode_t * target_dir;

	if(from_entry  == NULL) return;

	/* Find to */
	assert(in_to_path[0] == '/');

	char * to_path = copy_and_trim_path(in_to_path);

	char ** to_parts = NULL;
	int num_to_parts = split_path(to_path + 1, &to_parts);
	char * new_name = to_parts[num_to_parts - 1];

	file_entry_t * to_entry = find_entry_in_cache((const char**) to_parts, num_to_parts);

	if(to_entry != NULL) {
		msfs_error = -EEXIST;
		goto rename_file_cleanup;
	} else {
		reset_error();
	}

	to_entry = find_entry_in_cache((const char**) to_parts, num_to_parts - 1); /* Find parent of to */

	if(to_entry == NULL) {
		goto rename_file_cleanup;
	}

	from_dir = read_inode(from_entry->parent_inode);
	to_dir = read_inode(to_entry->address);

	if(!is_directory(&to_dir)) {
		msfs_error = -ENOTDIR;
		goto rename_file_full_cleanup;
	}

	unlist_file_entry(from_entry, &from_dir, 1);

	file_entry_t new_file_entry;
	new_file_entry.address = from_entry->address;
	new_file_entry.len = strlen(new_name) + 1;
	new_file_entry.name = new_name;
	new_file_entry.path = NULL;

	target_dir = &to_dir;

	if(to_dir.attributes.st_ino == from_dir.attributes.st_ino) target_dir = &from_dir;

	add_file_entry(&new_file_entry, target_dir);

rename_file_full_cleanup:

	free_file_entry(to_entry);

rename_file_cleanup:

	free_file_entry(from_entry);

	free(to_parts);
	free(to_path);

}

void add_file_entry(file_entry_t * file, inode_t * dir) {
	printf("Add file entry (len: %u, addr: %u, name: %s) to inode %lu\n", file->len, file->address, file->name, dir->attributes.st_ino);

	size_t cur_size = dir->attributes.st_size;
	if(!is_directory(dir)) {
		msfs_error = -ENOTDIR;
		return;
	}

	if(cur_size > 0) cur_size -= sizeof(addr_t) * 2; //Remove last entry (terminating null entry)

	write_inode_data(dir, cur_size, sizeof(addr_t)*2, (char*)file);

	/*
	file_entry_t test;
	read_inode_data(dir, cur_size, sizeof(addr_t) * 2, (char*) &test);
	if(test.len != file->len) {
		printf("Error: read data: %u, %u\n", test.len, test.address);
		abort();
	}
	*/

	cur_size += sizeof(addr_t) * 2;
	write_inode_data(dir, cur_size, file->len , file->name);
	cur_size += file->len;

	//Add terminating null entry
	write_inode_data(dir, cur_size, sizeof(addr_t)*2, zeroes);
	cur_size += sizeof(addr_t) * 2;

	dir->attributes.st_mtime = time(NULL);
	dir->attributes.st_size = cur_size;


	write_inode(dir);

	inode_t f_inode = read_inode(file->address);
	f_inode.attributes.st_nlink += 1;
	write_inode(&f_inode);
}

static inode_t create_blank_inode(mode_t mode) {
	inode_t inode;
	memset(&inode.attributes, 0, sizeof(inode.attributes));
	inode.attributes.st_ino = allocate_block();
	inode.next_block = 0;
	inode.attributes.st_blocks = 1;
	inode.attributes.st_atime = time(NULL);
	inode.attributes.st_mtime = time(NULL);
	inode.attributes.st_ctime = time(NULL);
	inode.attributes.st_uid = getuid();
	inode.attributes.st_gid = getuid();
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

inode_t create_inode_from_path(const char * in_path, mode_t mode) {
	char * path = copy_and_trim_path(in_path);
	char * last_slash = strrchr(path, '/');
	inode_t inode,  dir;
	if(last_slash == NULL) {
		msfs_error = -ENOENT;
		return inode;
	}
	*last_slash = '\0'; //Set this char to null to terminate this path
	++last_slash; //Increase to point to filename
	if(strlen(last_slash) <= 0) {
		msfs_error = -ENOENT;
		return inode;
	}

	if(strlen(path) > 0)
		dir = inode_from_path(path);
	else
		dir = inode_from_path("/");

	if(msfs_error != 0) {
		free(path);
		return inode;
	}

	if(!check_access(&dir, O_CREAT)) {
		msfs_error = -EPERM;
		free(path);
		return inode;
	}

	inode = create_inode(&dir, last_slash, mode);
	free(path);
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
		//Create self link
		file_entry_t link_entry;
		link_entry.address = inode.attributes.st_ino;
		link_entry.len = 2;
		link_entry.name = (char*)".";
		add_file_entry(&link_entry, &inode);

		//Create parent link
		link_entry.address = in_dir->attributes.st_ino;
		link_entry.len = 3;
		link_entry.name = (char*)"..";
		add_file_entry(&link_entry, &inode);
	}

	file_entry_t file_entry;
	file_entry.address = inode.attributes.st_ino;
	file_entry.len = strlen(name) + 1;
	file_entry.name = (char*) malloc(file_entry.len);
	strcpy(file_entry.name,name);
	add_file_entry(&file_entry, in_dir);
	free(file_entry.name);

	return inode;
}

static void delete_inode(inode_t * inode) {
	uncache_inode(inode); //nuke cache
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

/*
 * @return Number of read bytes
 */
int read_inode_data(inode_t * inode, size_t offset, size_t size, char * data) {
	if((unsigned int) (offset + size) > inode->attributes.st_size) {
		size = inode->attributes.st_size - offset;
	}

	if(size <= 0) {
		return 0;
	}

	inode_addr_t start_addr = find_addr_in_inode(inode, offset);
	inode_addr_t end_addr = find_addr_in_inode(inode, offset + size);

	/*printf("Start addr: {block index: %d, block_addr: 0x%x, addr in block: %d }\n",
			start_addr.block_index, start_addr.block_addr, start_addr.addr_in_block);

	printf("End addr: {block index: %d, block_addr: 0x%x, addr in block: %d }\n",
			end_addr.block_index, end_addr.block_addr, end_addr.addr_in_block);*/

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

	if(end_addr.block_index != start_addr.block_index && end_addr.addr_in_block != 0) { //If 0 the last block is not needed
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

	if(end_addr.block_index != start_addr.block_index) {
		write_data(end_addr.block_addr, data + data_offset, 0, end_addr.addr_in_block);
	}

	if((ssize_t) (offset + size) > inode->attributes.st_size) {
		inode->attributes.st_size = offset + size;
	}
	inode->attributes.st_atime = time(NULL);
	inode->attributes.st_mtime = time(NULL);
	write_inode(inode);

	return size;
}

int is_directory(const inode_t * inode) {
	return S_ISDIR(inode->attributes.st_mode);
}


/* Makes sure there is enought space in the fbl_addr list
 * to access the given index
 */
static void check_fbl_size(int index) {
	while(index >= num_alloc_fbls) {
		num_alloc_fbls *= 2;
		fbl_addr = (addr_t*) realloc(fbl_addr, num_alloc_fbls * sizeof(addr_t));
	}
}

/*
 * fills fbl_addr with data from the file system
 */
static void fill_fbl_addr() {
	char * fbl = get_fbl(0);
	if(msfs_error != 0) return;
	addr_t * next_addr = (addr_t*) fbl;
	int index = 1;

	while( *next_addr != 0 ){
		check_fbl_size(index);

		fbl_addr[index] = *next_addr;
		++num_fbls;
		fbl = get_fbl(index++);
		if(msfs_error != 0) return;
		next_addr = (addr_t*) fbl;
	}
}

/*
 * Fetches (or creates) the fbl with the given index
 */
static char* get_fbl(int index) {
	if(index >= num_fbls) {
		check_fbl_size(index);
		fbl_addr[index] = FREE_BLOCK_LIST_BLOCKS * index;	// Address to the first block in this list
														// this block will always be free, since this list does not yet exist

		// Write zeroes to the block:
		write_block(fbl_addr[index], zeroes);
		++num_fbls;
		fbl_pos_t fbl_pos = {
			/* index = */ index,
			/* char_index =  */ 0,
			/* bit_pos = */ 0
		};
		//Mark block in use
		mark_block_from_pos(&fbl_pos, 1);
	}

	read_block(fbl_addr[index], block);
	return block;
}

/*
 * Read a bit from a char
 */
static inline char read_bit(char c, short pos) {
	return (c >> pos) & 1;
}

void mark_block_from_pos(const fbl_pos_t * fbl_pos, char bit_value) {
	check_fbl_size(fbl_pos->index);
	if(fbl_pos->index >= num_fbls) {
		printf("index is larger than num fbls\n");
		abort();
	}
	/*
		char * fbl = get_fbl(num_fbls - 1);
		addr_t * next_addr = (addr_t*) fbl;

		addr_t addr = allocate_block();
		*next_addr = addr;
		fbl_addr[num_fbls] = addr;
		++num_fbls;
	*/

	char * fbl = get_fbl(fbl_pos->index);
	char * c = fbl + (ADDR_SIZE + fbl_pos->char_index);
	if(read_bit(*c, fbl_pos->bit_pos) == bit_value) return;
	//We know the bit shall be flipped, and can just xor it with 1
	*c ^= 1 << fbl_pos->bit_pos;
	//Write the block:
	write_block(fbl_addr[fbl_pos->index], fbl);
}

/*
 * Calculate the fbl position from a address
 */
static void calc_fbl_pos(const addr_t addr, fbl_pos_t * pos) {
	pos->index = addr / FREE_BLOCK_LIST_BLOCKS;
	addr_t internal_pos = addr % FREE_BLOCK_LIST_BLOCKS;
	pos->char_index = (int) floor(internal_pos / 8);
	pos->bit_pos = internal_pos % 8;
}

fbl_pos_t mark_block(const addr_t addr, char bit_value) {
	fbl_pos_t pos;
	calc_fbl_pos(addr, &pos);
	mark_block_from_pos(&pos, bit_value);

	return pos;
}

/*
 * Finds the next free block following the addr prev
 * fbl_pos stores the last fbl pos to speedup following lookups
 */
addr_t next_free_block(const addr_t prev, fbl_pos_t * fbl_pos) {
	addr_t cur = prev + 1;
	calc_fbl_pos(cur, fbl_pos);
	while( 1 ) {
		if( read_bit( get_fbl(fbl_pos->index)[ADDR_SIZE + fbl_pos->char_index], fbl_pos->bit_pos) == 0) {
			return cur;
		}
		++cur;
		calc_fbl_pos(cur, fbl_pos);
	};
}

int check_access(const inode_t * inode, int flags) {
	//TODO
	return 1;
}

//Bumps atime and writes inode
void bump_atime(inode_t * inode) {
	inode->attributes.st_atime = time(NULL);
	write_inode(inode);
}

static char * copy_and_trim_path(const char * path) {
	char * new_path = strdup(path);
	if(strlen(new_path) > 1 && new_path[strlen(new_path) - 1] == '/') {
		new_path[strlen(new_path) - 1] = '\0';
	}
	return new_path;
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

void format() {
	//Start by creating signature block:
	memcpy(block, zeroes, BLOCK_SIZE);
	strcpy(block, HEADER_TEXT);
	char * pos = block + strlen(HEADER_TEXT) + 1;
	addr_t tmp = VERSION;
	memcpy(pos, &tmp, sizeof(addr_t));
	pos += sizeof(addr_t);
	tmp = BLOCK_SIZE;
	memcpy(pos, &tmp, sizeof(addr_t));
	write_block(SIGNATURE_BLOCK, block);
	//Initial fbl:
	memcpy(block, zeroes, BLOCK_SIZE);
	pos = block + sizeof(addr_t); //First comes the next pointer
	pos[0] = 7;
	write_block(ROOT_FBL, block);

	//Next up: root directory file node

	inode_t inode; //Create the node
	inode.attributes.st_ino = ROOT_NODE;
	inode.next_block = 0;
	inode.attributes.st_blocks = 1;
	inode.attributes.st_atime = time(NULL);
	inode.attributes.st_mtime = time(NULL);
	inode.attributes.st_ctime = time(NULL);
	inode.attributes.st_nlink = 0;
	inode.attributes.st_size = 0;
	inode.attributes.st_blksize = BLOCK_SIZE;
	inode.attributes.st_mode = S_IFDIR | 755;

	for(unsigned int i=0; i< INODE_BLOCKS; ++i) {
		inode.block_addr[i] = 0;
	}

	write_inode(&inode);

	file_entry_t entry;
	entry.len = 2;
	entry.address = ROOT_NODE;
	entry.name = (char*)".";
	add_file_entry(&entry, &inode);
	entry.len = 3;
	entry.name = (char*)"..";
	add_file_entry(&entry, &inode);

}

void reset_error() { msfs_error = 0; }

void print_fbl() {
	int l = 0;
	addr_t addr = 0;
	fbl_pos_t pos;

	unsigned long long in_use = 0;

	calc_fbl_pos(addr, &pos);
	for(;pos.index < num_fbls; calc_fbl_pos(++addr, &pos)) {
		++l;
		short bit = read_bit(get_fbl(pos.index)[ADDR_SIZE + pos.char_index], pos.bit_pos);
		in_use += bit;
		if(pos.index < 10) {
			printf("%d", bit);
			if(l % 256 == 0) printf("\n");
		}
	}
	printf("\n\n%llu blocks in use\n", in_use);
}

static void clear_file_cache() {
	for(file_cache_it_t it = files.begin(); it != files.end(); ++it) {
		free_file_entry(it->second);
	}

	files.clear();

	file_entry_t tmp;
	tmp.len = 2;
	tmp.address = ROOT_NODE;
	tmp.parent_inode = 0;
	tmp.name = (char*)"/";
	tmp.path = (char*)"/";

	files["/"] = clone_entry(&tmp); //Always cache "/"
}

void clear_cache() {
	for(int i = 0; i< CACHE_SIZE; ++i) {
		block_cache[i].valid = 0;
	}

	for(int i = 0; i< INODE_INDEX_CACHE_SIZE; ++i) {
		block_cache[i].valid = 0;
	}

	clear_file_cache();
}
