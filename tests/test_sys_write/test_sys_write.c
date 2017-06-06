#include "../stampwait.h"

#include <stdio.h>

int main(int argc, const char **argv) {
    int err = stampwait(argv[1]);
    if (err != 0) {
        fprintf(stderr, "stampwait failed\n");
        return 1;
    }
    int fd = open("/tmp/test_sys_write", O_RDWR | O_CREAT, 0755);
    if(fd < 0)
        return 1;

    if (write(fd, "42", 1) != 1) {
        close (fd);
        return -1;
    }

    char buf[1];

    if(read(fd, buf, 1) < 0) {
        close (fd);
        return -1;
    }

    close(fd);
    return 0;
}
