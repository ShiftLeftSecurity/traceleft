#include "../stampwait.h"

#include <stdio.h>

int main(int argc, const char **argv)
{
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

	// sleep 10ms so we have time to get the fd_install event
	usleep(10 * 1000);

	char buf[1];

	if (read(fd, buf, 1) < 0) {
		close(fd);
		return -1;
	}

	close(fd);

	// sleep 10ms so the process doesn't die before we check
	// /proc/$PID/root/$FILE_PATH
	usleep(10* 1000);

	return 0;
}
