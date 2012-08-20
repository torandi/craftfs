#include "msfbl.h"

#include <cstdlib>
#include <map>

static std::map<const char *, addr_t> files;

static addr_t * fbl_addr;
static int num_fbls, num_alloc_fbls; //Actual number, allocated in local list, num_alloc >= num_fbls

static char[BLOCK_SIZE] active_fbl;
static int active_fbl_index;

// Split path into parts
static char ** split_path( const char * path);
// Free path created by split_path
static void free_path(char ** path);

static addr_t find_entry_internal_path(const char ** path, addr_t node);

static void read_fbl_addresses();

static char * zeroes; //BLOCK_SIZE of zeros

void init() {
	zeroes = calloc(BLOCK_SIZE, 1);

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
	char * c =  + (ADDR_SIZE + fbl_pos->char_index);
	if(read_bit(*c) == bit) return;
	//We know the bit shall be flipped, and can just xor it with 1
	*c ^= 1 << fbl_pos->bit_pos; 
	//Write the block:
	write_block(fbl_addr[fbl_pos->index], fbl);
}

void mark_block(const addr_t addr, char bit) {
	fbl_pos_t pos;
	pos.index = cur / FREE_BLOCK_LIST_BLOCKS;
	addr_t internal_pos = addr % FREE_BLOCK_LIST_BLOCKS;
	pos.char_index = (int) floor(internal_pos / 8);
	pos.bit_pos = internal_pos % FREE_BLOCK_SIZE;

	mark_block_from_pos(&pos, bit);
}

addr_t next_free_block(const addr_t prev, fbl_pos_t * fbl_pos) {
	addr_t cur = prev + 1;
	int fbl_index = cur / FREE_BLOCK_LIST_BLOCKS;
	while(fbl_index < num_fbls) {
		addr_t internal_pos = cur % FREE_BLOCK_LIST_BLOCKS;
		short char_index = (int) floor(internal_pos / 8);
		short bit_pos = internal_pos % FREE_BLOCK_SIZE;
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
