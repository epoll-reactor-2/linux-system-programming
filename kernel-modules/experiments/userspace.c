#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>

int main() {
	int fd = open("/dev/template_device", O_RDWR);
	if (fd < 0)
		return 1;

	int ret = ioctl(fd, 0xFFAC, 8);
	if (ret < 0) {
		perror("ioctl()");
		return 2;
	}

	printf("ioctl() succeed\n");

	return 0;
}