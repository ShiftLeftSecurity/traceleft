#include <unistd.h>
#include <fcntl.h>

static inline int stampwait(const char *path) {
	int fd = open(path, O_CREAT, 0755);
	if (fd < 0)
		return 1;
	close(fd);
	// wait until the file is removed by run.sh
	while (access(path, F_OK) != -1)
		sleep(1);
	sleep(1);
	return 0;
}
