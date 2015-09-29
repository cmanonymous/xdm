#include "common.h"

#define SOCK_BACKLOG 5

int sock_set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if(flags < 0) {
		return -1;
	}

	flags |= O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) < 0) {
		return -1;
	}

	return 0;
}

int sock_clear_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if(flags < 0) {
		return -1;
	}

	flags &= ~O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) < 0) {
		return -1;
	}

	return 0;
}

int sock_set_timeout(int fd, int timeout)
{
	struct timeval tv;
	int ret;

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

	return ret && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));
}

int sock_set_reuseaddr(int fd)
{
	int reuseaddr = 1;

	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));
}

int sock_create()
{
	return socket(AF_INET, SOCK_STREAM, 0);
}

void sock_close(int fd)
{
	close(fd);
}

int sock_bind(int fd, struct sockaddr *addr)
{
	return bind(fd, addr, sizeof(struct sockaddr));
}

int sock_listen(int fd)
{
	return listen(fd, SOCK_BACKLOG);
}

int sock_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	return accept(fd, addr, addrlen);
}

int sock_connect(int fd, struct sockaddr *addr)
{
	return connect(fd, addr, sizeof(struct sockaddr));
}

int sock_read(int fd, void *buf, size_t size)
{
	return read_n(fd, buf, size);
}

int sock_write(int fd, void *buf, size_t size)
{
	return write_n(fd, buf, size);
}

int sock_get_addr(const char *ip, const char *port, struct sockaddr *addr)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int ret = 0; 

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(ip, port, &hints, &res);
	if(!ret)
		memcpy(addr, res->ai_addr, sizeof(struct sockaddr));
	freeaddrinfo(res);
	return ret;
}

int sock_server_create(struct sockaddr *addr)
{
	int fd;
	int ret;

	fd = sock_create();
	if(fd < 0) {
		return -1;
	}

	ret = sock_set_reuseaddr(fd);
	if(ret < 0) {
		goto err_server;
	}

	ret = sock_bind(fd, addr);
	if(ret < 0) {
		goto err_server;
	}

	ret = sock_listen(fd);
	if(ret < 0) {
		goto err_server;
	}

	return fd;

err_server:
	sock_close(fd);

	return -1;
}

int make_server(const char *host, const char *port)
{
	struct sockaddr addr;
	int fd;
	int ret;

	ret = sock_get_addr(host, port, &addr);
	if(ret < 0) {
		return -1;
	}

	fd = sock_server_create(&addr);
	if(fd < 0) {
		return -1;
	}

	return fd;
}
