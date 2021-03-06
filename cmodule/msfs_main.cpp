#include "msfs.cpp"

#include <cstring>
#include <cstdio>


int main(int argc, char ** argv) {
	int err = init("minecraft.dev", 1);
	if(err != 0) return err;

	struct fuse_operations op = {0};
		op.getattr  = msfs_getattr;
		op.opendir = msfs_opendir;
		op.readdir = msfs_readdir;
		op.ftruncate = msfs_ftruncate;
		op.create = msfs_create;
		op.open   = msfs_open;
		op.read   = msfs_read;
		op.write   = msfs_write;
		op.mkdir = msfs_mkdir;
		op.unlink = msfs_unlink;
		op.rmdir = msfs_rmdir;
		op.destroy = msfs_destroy;
		op.rename = msfs_rename;
		op.fsync = msfs_fsync;
		op.fsyncdir = msfs_fsync;

	return fuse_main(argc, argv, &op, NULL);
}
