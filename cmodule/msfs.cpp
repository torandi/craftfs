#include "msfslib.h"
#include <stdio.h>
#include <errno.h>
#include <cstring>
#include "timer.h"

static int msfs_getattr(const char *path, struct stat *stbuf) {
	printf("msfs_getattr(%s)\n", path);
	reset_error();
	inode_t inode = inode_from_path(path);
	if(msfs_error != 0) return msfs_error;
	*stbuf = inode.attributes;
	printf("msfs_getattr(%s), found.\n", path);
	return 0;
}

static int msfs_opendir(const char * path, fuse_file_info * fi)  {
	printf("msfs_opendir(%s)\n", path);
	reset_error();
	inode_t inode = inode_from_path(path);
	if(msfs_error != 0) return msfs_error;
	if(!is_directory(&inode)) return -ENOTDIR;
	if(!check_access(&inode, fi->flags)) return -EPERM;
	fi->fh = (uint64_t) inode.attributes.st_ino;
	printf("msfs_opendir(%s) found inode %lu\n", path, inode.attributes.st_ino);
	return 0;
}

static int msfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, fuse_file_info *fi) {
	reset_error();
	printf("msfs_readdir(%s) inode %lu\n", path, fi->fh);
	inode_t entry_inode, inode = read_inode((addr_t)fi->fh);
	if(msfs_error != 0) return msfs_error;

	bump_atime(&inode);

	addr_t addr = 0;
	file_entry_t * entry;

	entry = next_file_entry(&inode, &addr);

	while(entry != NULL) {
		entry_inode = read_inode(entry->address);
		filler(buf, entry->name, &entry_inode.attributes, 0);
		free_file_entry(entry);
		entry = next_file_entry(&inode, &addr);
	}
	return msfs_error;
}

static int msfs_create(const char * path, mode_t mode, struct fuse_file_info * fi) {
	printf("msfs_create(%s), mode: %u\n", path, mode);
	reset_error();
	inode_t inode = create_inode_from_path(path, mode);
	if(msfs_error != 0) return msfs_error;
	fi->fh = inode.attributes.st_ino;
	return msfs_error;
}

static int msfs_mkdir(const char * path, mode_t mode) {
	reset_error();
	create_inode_from_path(path, mode | S_IFDIR);
	if(msfs_error != 0) return msfs_error;
	return msfs_error;
}

static int msfs_open(const char *path, fuse_file_info *fi) {
	printf("msfs_open(%s)\n", path);
	reset_error();
	inode_t inode = inode_from_path(path);
	if(msfs_error != 0) return msfs_error;
	if(is_directory(&inode)) return -EISDIR;
	if(!check_access(&inode, fi->flags)) return -EPERM;
	printf("Lock owner: %lu\n", fi->lock_owner);
	fi->fh = (uint64_t) inode.attributes.st_ino;
	return msfs_error;

}

static int msfs_ftruncate(const char * path, off_t off, struct fuse_file_info * fi) {
	printf("msfs_ftruncate(%s)\n", path);
	reset_error();
	inode_t inode = read_inode((addr_t)fi->fh);
	if(msfs_error != 0) return msfs_error;
	if(!check_access(&inode, O_TRUNC)) return -EPERM;
	inode.attributes.st_size = (addr_t) off;
	write_inode(&inode);
	return msfs_error;
}

static int msfs_read(const char *path, char *buf, size_t size, off_t offset, fuse_file_info *fi) {
	printf("msfs_read(%s)\n", path);
	reset_error();
	inode_t inode = read_inode((addr_t)fi->fh);
	if(msfs_error != 0) return msfs_error;

	bump_atime(&inode);

	int bytes = read_inode_data(&inode, offset, size, buf);
	if(msfs_error != 0) return msfs_error;
	return bytes;
}

static int msfs_write(const char *path, const char *data, size_t size, off_t offset, fuse_file_info *fi) {
	printf("msfs_write(%s)\n", path);
	reset_error();
	inode_t inode = read_inode((addr_t)fi->fh);
	if(msfs_error != 0) return msfs_error;

	int bytes = write_inode_data(&inode, offset, size, data);
	if(msfs_error != 0) return msfs_error;
	return bytes;
}

static int msfs_rm (file_entry_t * entry, int recursive) {
	if(entry == NULL) return -ENOENT;
	if(msfs_error != 0) return msfs_error;

	inode_t inode = read_inode(entry->address);

	addr_t cur_addr = 0;
	int ret;

	if(recursive && is_directory(&inode)) {
		file_entry_t * file_entry;
		for(file_entry = next_file_entry(&inode, &cur_addr); file_entry != NULL; file_entry = next_file_entry(&inode, &cur_addr)) {
			if(strcmp(file_entry->name, ".") != 0 && strcmp(file_entry->name, "..") != 0) {
				ret = msfs_rm(file_entry, 1);
				if(ret != 0) return ret;
			}
			free_file_entry(file_entry);
		}
	}

	delete_file_entry(entry);
	free_file_entry(entry);
	return msfs_error;
}

static int msfs_unlink ( const char * path) {
	reset_error();
	file_entry_t * entry = find_entry(path);
	return msfs_rm(entry, 0);
}

static int msfs_rmdir ( const char * path) {
	reset_error();
	file_entry_t * entry = find_entry(path);
	return msfs_rm(entry, 1);
}

static void msfs_destroy(void * ptr) {
	reset_error();
	cleanup();
}

static int msfs_rename(const char * from, const char * to) {
	reset_error();
	rename_file(from, to);
	return msfs_error;
}

static int msfs_fsync(const char *, int, struct fuse_file_info *) {
	printf("SYNC!\n");
	clear_cache();
	return 0;
}
