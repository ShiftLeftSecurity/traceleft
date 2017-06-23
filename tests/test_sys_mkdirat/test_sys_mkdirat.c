#include "../stampwait.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, const char **argv)
{
	int err = stampwait(argv[1]);
	if (err != 0) {
		fprintf(stderr, "stampwait failed\n");
		return 1;
	}

	// if test_mkdir exists, we remove it first
	DIR *dir = opendir("/tmp/traceleft-trace-out/test_mkdirat");
	if (dir) {
		closedir(dir);
		int status = rmdir("/tmp/traceleft-trace-out/test_mkdirat");
		if (status < 0) {
			fprintf(stderr, "rmdir failed\n");
			return 1;
		}
	}

	// pathname is absolute here, so dfd will be ignored, so we set it ourselves
	int ret = mkdirat(42, "/tmp/traceleft-trace-out/test_mkdirat", 0755);
	if (ret < 0) {
		fprintf(stderr, "mkdirat failed\n");
		return 1;
	}

	return 0;
}
