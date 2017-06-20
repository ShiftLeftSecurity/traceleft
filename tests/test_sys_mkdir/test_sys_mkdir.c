#include "../stampwait.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
	int err = stampwait(argv[1]);
	if (err != 0) {
		fprintf(stderr, "stampwait failed\n");
		return 1;
	}

	// if test_mkdir exists, we remove it first
	DIR *dir = opendir("/tmp/traceleft-trace-out/test_mkdir");
	if (dir) {
		closedir(dir);
		int status = rmdir("/tmp/traceleft-trace-out/test_mkdir");
		if (status < 0) {
			fprintf(stderr, "rmdir failed\n");
			return 1;
		}
	}

	int ret = mkdir("/tmp/traceleft-trace-out/test_mkdir", 0755);
	if (ret < 0) {
		fprintf(stderr, "mkdir failed\n");
		return 1;
	}

	return 0;
}
