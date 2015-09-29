#ifndef BIO_HANDLER_H
#define BIO_HANDLER_H

#include <linux/bio.h>
#include <linux/blkdev.h>

extern MAKE_REQUEST_TYPE hadmdev_make_request(struct request_queue *q, struct bio *bio);

extern void read_bio_data(void *dest, struct bio *src);
extern void write_bio_data(struct bio *bio, void *src, size_t len);
extern void hadm_free_bio(struct bio *bio);

extern int bio_read_handler_run(void *arg);
extern int bio_write_handler_run(void *arg);

#endif	/* BIO_HANDLER_H */
