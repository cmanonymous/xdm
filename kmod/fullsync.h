#ifndef FULLSYNC_H
#define FULLSYNC_H

#include <linux/module.h>
#include <linux/blkdev.h>

extern int fullsync_md5_hash(const char *str, u32 len, u8 *hash);

#endif	/* FULLSYNC_H */
