#include "../stampwait.h"

#include <stdio.h>

int main(int argc, const char **argv) {
	int err = stampwait(argv[1]);
	if (err != 0) {
		fprintf(stderr, "stampwait failed\n");
		return 1;
	}
	int fd = open("/proc/cpuinfo", O_RDONLY, 0);
	if (fd < 0) {
		fprintf(stderr, "open failed\n");
		return 1;
	}

	char buf[1];

	if (read(fd, buf, 1) < 0) {
		close (fd);
		return -1;
	}

	close(fd);
	return 0;
}
