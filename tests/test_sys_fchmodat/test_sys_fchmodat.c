#include "../stampwait.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, const char **argv)
{
	int err = stampwait(argv[1]);
	if (err != 0) {
		fprintf(stderr, "stampwait failed\n");
		return 1;
	}
	int fd = open("/tmp/traceleft-trace-out/test_sys_fchmodat", O_RDWR | O_CREAT, 0755);
	if (fd < 0) {
		fprintf(stderr, "open failed\n");
		return 1;
	}

	close(fd);

	err = fchmodat(42, "/tmp/traceleft-trace-out/test_sys_fchmodat", 0777, 0);
	if (err != 0) {
		fprintf(stderr, "fchmodat failed\n");
		return 1;
	}

	return 0;
}
