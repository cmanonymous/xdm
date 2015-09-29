#ifndef __IO_H__
#define __IO_H__

ssize_t write_n(int fd, void *data, size_t size);

ssize_t read_n(int fd, void *data, size_t size);

#endif // __IO_H__
