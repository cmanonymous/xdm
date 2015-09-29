#include "common.h"

ssize_t write_n(int fd, void *data, size_t size)
{
	ssize_t ret;
	ssize_t n;
	unsigned char *p;

	n = 0;
	p = data;

	while(n < size) {
		ret = write(fd, p, size - n);

		if(ret <= 0) {
			if(errno == -EAGAIN) {
				continue;
			} else {
				log_error("Error: %s failed: %s", __func__, strerror(errno));
				return n;
			}
		}

		n += ret;
		p += ret;
	}

	return n;
}

ssize_t read_n(int fd, void *data, size_t size)
{
	ssize_t ret;
	ssize_t n;
	unsigned char *p;

	n = 0;
	p = data;

	while(n < size) {
		ret = read(fd, p, size - n);

		if(ret <= 0) {
			if(errno == -EAGAIN) {
				continue;
			} else {
				log_error("Error: read failed:%s\n", strerror(errno));
				return n;
			}
		}

		n += ret;
		p += ret;
	}

	return n;
}
