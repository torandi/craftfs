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
		op.open   = msfs_open;
		op.read   = msfs_read;
		op.destroy = msfs_destroy;

	return fuse_main(argc, argv, &op, NULL);
}
