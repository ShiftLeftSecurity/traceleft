#include "../stampwait.h"

#include <stdio.h>
#include <sys/stat.h>

int main(int argc, const char **argv)
{
	int err = stampwait(argv[1]);
	if (err != 0) {
		fprintf(stderr, "stampwait failed\n");
		return 1;
	}
	int fd = open("/tmp/traceleft-trace-out/test_fd", O_RDWR | O_CREAT, 0755);
	if (fd < 0) {
		fprintf(stderr, "open failed\n");
		return 1;
	}
	char file_desc[2];
	snprintf(file_desc, 2, "%d", fd);

	if (write(fd, file_desc, 1) != 1) {
		close(fd);
		return -1;
	}

	err = fchown(fd, 0, 0);
	if (err != 0) {
		fprintf(stderr, "fchown failed\n");
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
