#include "common.h"

struct device *alloc_device()
{
	struct device *dev;

	dev = malloc(sizeof(struct device));
	if(dev == NULL) {
		return NULL;
	}

	memset(dev, 0, sizeof(struct device));
	dev->dfd = -1;
	dev->mfd = -1;
	pthread_spin_init(&dev->spinlock, PTHREAD_PROCESS_PRIVATE);

	return dev;
}

void free_device(struct device *dev)
{
	free(dev);
}

struct device *make_device(void)
{
	struct device *dev;
	struct queue *q;
	struct thread *thr;

	dev = alloc_device();
	if(dev == NULL) {
		return NULL;
	}

	dev->data_handler = kern_data_handler;
	dev->meta_handler = kern_meta_handler;

	q = init_queue();
	if(q == NULL) {
		free_device(dev);
		return NULL;
	}
	dev->data_q = q;

	q = init_queue();
	if(q == NULL) {
		free_queue(dev->data_q);
		free_device(dev);
		return NULL;
	}
	dev->meta_q = q;

	q = init_queue();
	if(q == NULL) {
		free_queue(dev->data_q);
		free_queue(dev->meta_q);
		free_device(dev);
		return NULL;
	}
	dev->work_q = q;

	thr = create_thread("dev:data_worker", "device_data_worker_function", device_data_worker_function, dev);
	if(thr == NULL) {
		goto err_data;
	}
	dev->data_worker = thr;

	thr = create_thread("dev:meta_worker", "device_meta_worker_function", device_meta_worker_function, dev);
	if(thr == NULL) {
		goto err_meta;
	}
	dev->meta_worker = thr;

	thr = create_thread("dev:worker", "device_worker_function", device_worker_function, dev);
	if(thr == NULL) {
		goto err_worker;
	}
	dev->worker = thr;

	return dev;

err_worker:
	free_thread(dev->meta_worker);

err_meta:
	free_thread(dev->data_worker);

err_data:
	free_device(dev);
	return NULL;
}

void dev_set_daemon(struct device *dev, struct daemon *daemon)
{
	dev->daemon = daemon;
}

struct device *init_device(struct daemon *daemon, struct config *cfg)
{
	struct device *dev = make_device();
	if( dev ) {
		dev_set_daemon(dev, daemon);
	}
	return dev;
}

void device_run(struct device *dev)
{
	thread_run(dev->data_worker);
	thread_run(dev->meta_worker);
	thread_run(dev->worker);
}

int dev_put_work_packet(struct device *dev, struct packet *pkt)
{
	struct entry *e;

	if (!pkt->node_to)
		return -1;
	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	return queue_put(e, dev->work_q);
}

struct packet *dev_get_work_packet(struct device *dev)
{
	struct entry *e;
	struct packet *pkt;

	e = queue_get(dev->work_q);
	if(e == NULL) {
		return NULL;
	}

	pkt = (struct packet *)e->data;
	free_entry(e);

	return pkt;
}

int dev_put_data_packet(struct device *dev, struct packet *pkt)
{
	struct entry *e;

	if (!pkt->node_to)
		return -1;
	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	return queue_put(e, dev->data_q);
}

struct packet *dev_get_data_packet(struct device *dev)
{
	struct entry *e;
	struct packet *pkt;

	e = queue_get(dev->data_q);
	if(e == NULL) {
		return NULL;
	}

	pkt = (struct packet *)e->data;
	free_entry(e);

	return pkt;
}

int dev_put_meta_packet(struct device *dev, struct packet *pkt)
{
	struct entry *e;

	if (!pkt->node_to)
		return -1;
	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	return queue_put(e, dev->meta_q);
}

struct packet *dev_get_meta_packet(struct device *dev)
{
	struct entry *e;
	struct packet *pkt;

	e = queue_get(dev->meta_q);
	if(e == NULL) {
		return NULL;
	}

	pkt = (struct packet *)e->data;
	free_entry(e);

	return pkt;
}

void dev_del_data_event(struct device *dev)
{
	pthread_spin_lock(&dev->spinlock);

	if(dev->data_event == NULL) {
		goto err;
	}

	event_free(dev->data_event);
	dev->data_event = NULL;

	sock_close(dev->dfd);
	dev->dfd = -1;
	pthread_spin_unlock(&dev->spinlock);

	clean_packet_queue(dev->data_q);

	return;

err:
	pthread_spin_unlock(&dev->spinlock);
}

void dev_del_meta_event(struct device *dev)
{
	pthread_spin_lock(&dev->spinlock);

	if(dev->meta_event == NULL) {
		goto err;
	}

	event_free(dev->meta_event);
	dev->meta_event = NULL;

	sock_close(dev->mfd);
	dev->mfd = -1;
	pthread_spin_unlock(&dev->spinlock);

	clean_packet_queue(dev->data_q);

	return;

err:
	pthread_spin_unlock(&dev->spinlock);
}
