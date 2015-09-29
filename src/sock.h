#ifndef __SOCK_H__
#define __SOCK_H__

int sock_set_nonblock(int fd);

int sock_clear_nonblock(int fd);

int sock_set_reuseaddr(int fd);

int sock_set_timeout(int fd, int timeout);

int sock_create();

void sock_close(int fd);

int sock_bind(int fd, struct sockaddr *addr);

int sock_listen(int fd);

int sock_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);

int sock_connect(int fd, struct sockaddr *addr);

int sock_read(int fd, void *buf, size_t size);

int sock_write(int fd, void *buf, size_t size);

int sock_get_addr(const char *ip, const char *port, struct sockaddr *addr);

int sock_server_create(struct sockaddr *addr);

int make_server(const char *host, const char *port);

#endif // __SOCK_H__
