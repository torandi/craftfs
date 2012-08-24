#include "msfslib.h"
#include <stdio.h>
#include <errno.h>

static int msfs_getattr(const char *path, struct stat *stbuf) {
	reset_error();
	inode_t inode = inode_from_path(path);
	if(msfs_error != 0) return msfs_error;
	*stbuf = inode.attributes;
	return 0;
}

static int msfs_opendir(const char * path, fuse_file_info * fi)  {
	reset_error();
	inode_t inode = inode_from_path(path);
	if(msfs_error != 0) return msfs_error;
	if(!is_directory(&inode)) return -ENOTDIR;
	printf("Lock owner: %lu\n", fi->lock_owner);
	fi->fh = (uint64_t) inode.attributes.st_ino;
	return 0;
}

static int msfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, fuse_file_info *fi) {
	reset_error();
	inode_t entry_inode, inode = read_inode((addr_t)fi->fh);
	if(msfs_error != 0) return msfs_error;

	printf("Offset: %lu\n", offset);
	addr_t addr = 0;
	file_entry_t * entry;

	for(entry = next_file_entry(&inode, &addr); entry != NULL; entry = next_file_entry(&inode, &addr)) {
		entry_inode = read_inode(entry->address);
		filler(buf, entry->name, &entry_inode.attributes, 0);
		free_file_entry(entry);
	}
	return msfs_error;
}

static int msfs_create(const char * path, mode_t mode, struct fuse_file_info * fi) {
	reset_error();
	inode_t inode = create_inode_from_path(path, mode);
	if(msfs_error != 0) return msfs_error;
	fi->fh = inode.attributes.st_ino;
	return msfs_error;
}

static int msfs_open(const char *path, fuse_file_info *fi) {
	reset_error();
	inode_t inode = inode_from_path(path);
	if(msfs_error != 0) return msfs_error;
	if(is_directory(&inode)) return -EISDIR;
	printf("Lock owner: %lu\n", fi->lock_owner);
	fi->fh = (uint64_t) inode.attributes.st_ino;
	return msfs_error;

}

static int msfs_ftruncate(const char * path, off_t off, struct fuse_file_info * fi) {
	reset_error();
	inode_t inode = read_inode((addr_t)fi->fh);
	if(msfs_error != 0) return msfs_error;
	inode.attributes.st_size = (addr_t) off;
	write_inode(&inode);
	return msfs_error;
}

static int msfs_read(const char *path, char *buf, size_t size, off_t offset, fuse_file_info *fi) {
	reset_error();

	return -1;
}

static void msfs_destroy(void * ptr) {
	reset_error();
	cleanup();
}
