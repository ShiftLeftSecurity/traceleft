#include "../stampwait.h"

#include <stdio.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
	int err = stampwait(argv[1]);
	if (err != 0) {
		fprintf(stderr, "stampwait failed\n");
		return 1;
	}
	int fd = open("/tmp/traceleft-trace-out/test_sys_chown", O_RDWR | O_CREAT, 0755);
	if (fd < 0) {
		fprintf(stderr, "open failed\n");
		return 1;
	}

	close(fd);

	err = chown("/tmp/traceleft-trace-out/test_sys_chown", 0, 0);
	if (err != 0) {
		fprintf(stderr, "chown failed\n");
		return 1;
	}

	return 0;
}
