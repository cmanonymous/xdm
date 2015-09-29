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

/* kmod 节点是需要发送的目标节点时返回 1，否则返回 0 */
int device_is_target(struct device *dev, int kmod_to)
{
	return (1 << dev->id) & kmod_to;
}

/* device是否可以接收数据
 */
int device_want_recv(struct device *dev)
{
	return dev->dfd > 0 && dev->mfd > 0;
}

int device_disconnect(struct device *dev)
{
	int i, ret;
	struct packet *pkt, *notify;
	struct node *node;
	struct daemon *daemon = dev->daemon;

	pkt = alloc_packet0();
	if (!pkt) {
		log_error("Error: %s alloc packet failed", __func__);
		return -ENOMEM;
	}
	pkt->type = P_KMOD_DISCONN;
	pkt->dev_id = MAX_DEVICES;
	pkt->node_from = daemon->local_node->id;
	pkt->kmod_from = dev->id;
	pkt->kmod_to = -1;

	for (i = 0; i < daemon->node_list->node_num; i++) {
		node = daemon->node_list->nodes[i];
		if (!node_available(node))
			continue;
		notify = packet_clone(pkt);
		if (!notify) {
			log_error("alloc disconnect notify packet failed.");
			ret = -ENOMEM;
			goto out;
		}
		packet_set_node_to(node->id, notify);
		ret = node_put_meta_packet(node, notify);
		if (ret < 0) {
			log_error("Error: put meta packet failed.");
			free_packet(notify);
			goto out;
		}
	}
out:
	free_packet(pkt);
	return ret;
}

struct device *make_device(int id)
{
	struct device *dev;
	struct queue *q;
	struct thread *thr;

	dev = alloc_device();
	if(dev == NULL) {
		return NULL;
	}

	dev->id = id;
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

	thr = create_thread(device_data_worker_function, dev);
	if(thr == NULL) {
		goto err_data;
	}
	dev->data_worker = thr;

	thr = create_thread(device_meta_worker_function, dev);
	if(thr == NULL) {
		goto err_meta;
	}
	dev->meta_worker = thr;

	return dev;

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

int dev_put_data_packet_force(struct device *dev, struct packet *pkt,
		cb_fn *callback, void *data)
{
	int ret;
	struct entry *e;

	e = create_cb_entry(pkt, callback, data);
	if(e == NULL) {
		return -1;
	}

	ret = queue_put_force(e, dev->data_q);
	if (ret < 0)
		free_entry(e);

	return ret;
}

int dev_put_data_packet(struct device *dev, struct packet *pkt)
{
	struct entry *e;

	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	if(queue_put(e, dev->data_q) < 0){
		free_entry(e);
		return -1;
	}
	return 0;
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

	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}
	/**
	 *因为meta的数据非常少，如果队列满了，说明
	 *连接出现问题，这时候需要关闭连接
	 */

	if(queue_put_nonblock(e, dev->meta_q) < 0){
		free_entry(e);
		return -1;
	}
	return 0;
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

// FIXME see dev_del_meta_event()
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

	device_disconnect(dev);

	return;

err:
	pthread_spin_unlock(&dev->spinlock);
}

/* FIXME
 * meta/data 链路如果其中一条断掉了，需要怎么做？
 * 应该是都连上了该device的状态才是可用的，需要
 * 做一些标记
 */
void dev_del_meta_event(struct device *dev)
{
	pthread_spin_lock(&dev->spinlock);

	if(dev->meta_event == NULL) {
		goto out;
	}

	event_free(dev->meta_event);
	dev->meta_event = NULL;

	sock_close(dev->mfd);
	dev->mfd = -1;
out:
	pthread_spin_unlock(&dev->spinlock);

	clean_packet_queue(dev->data_q);

	device_disconnect(dev);

	return;
}

int device_list_resize(struct device_list *dev_list)
{
	struct device **devs;
	struct device **tmp;
	int size;

	size = dev_list->max_num + (dev_list->max_num * 3) / 2;
	devs = calloc(size, sizeof(*devs));
	if (!devs)
		return -1;
	dev_list->max_num = size;

	tmp = dev_list->devs;
	memcpy(devs, tmp, dev_list->dev_num * sizeof(*devs));

	dev_list->devs = devs;
	free(tmp);

	return 0;
}

int device_list_put(struct device_list *dev_list, struct device *dev)
{
	dev_list->devs[dev_list->dev_num] = dev;
	dev_list->dev_num += 1;

	return (dev_list->dev_num == dev_list->max_num) ? device_list_resize(dev_list) : 0;
}

struct device_list *create_device_list(int max_num)
{
	struct device_list *dev_list;

	dev_list = malloc(sizeof(*dev_list));
	if (!dev_list)
		return NULL;

	dev_list->devs = calloc(max_num, sizeof(*dev_list->devs));
	if (!dev_list->devs)
		goto free_dev_list;
	dev_list->max_num = max_num;
	dev_list->dev_num = 0;

	return dev_list;

free_dev_list:
	free(dev_list);
	return NULL;
}

void free_device_list(struct device_list *dev_list)
{
	int i;
	struct device *dev;

	for (i = 0; i < dev_list->dev_num; i++) {
		dev = dev_list->devs[i];
		if (!dev)
			continue;
		free_device(dev);
	}
}

struct device_list *init_device_list(struct daemon *daemon, struct config *cfg)
{
	int idx;
	struct device *dev;
	struct device_list *dev_list;
	struct node_config *node_cfg;

	dev_list = create_device_list(cfg->node_num);
	if (!dev_list) {
		log_error("failed to create device list");
		return NULL;
	}

	for (idx = 0; idx < cfg->node_num; idx++) {
		node_cfg = &cfg->nodes[idx];
		dev = make_device(node_cfg->id);
		if (!dev) {
			log_error("failed to create kmod device %d", node_cfg->id);
			goto free_dev_list;
		}
		dev_set_daemon(dev, daemon);
		device_list_put(dev_list, dev);
	}

	return dev_list;

free_dev_list:
	free_device_list(dev_list);
	return NULL;
}

struct device *find_device(struct device_list *dev_list, int dev_id)
{
	int i;
	struct device *dev;

	for (i = 0; i < dev_list->dev_num; i++) {
		dev = dev_list->devs[i];
		if (dev->id == dev_id)
			return dev;
	}

	return NULL;
}

void device_list_run(struct device_list *dev_list)
{
	int i;
	struct device *dev;

	for (i = 0; i < dev_list->dev_num; i++) {
		dev = dev_list->devs[i];
		thread_run(dev->data_worker);
		thread_run(dev->meta_worker);
	}
}

void pr_device(struct device *dev)
{
	printf("\t\tid: %d\n", dev->id);
	printf("\t\tdfd: %d, event: %p, handler: %p\n", dev->dfd, dev->data_event, dev->data_handler);
	printf("\t\tmfd: %d, event: %p, handler: %p\n", dev->mfd, dev->meta_event, dev->meta_handler);
	printf("\t\tdata_q: %p, meta_q: %p\n", dev->data_q, dev->meta_q);
	printf("\t\tdata_worker: %p, meta_worker: %p\n", dev->data_worker, dev->meta_worker);
}

void pr_device_list(struct device_list *dev_list)
{
	struct device *dev;
	int i;

	printf("max_num: %d, dev_num: %d\n", dev_list->max_num, dev_list->dev_num);
	printf("local_idx: %d\n", dev_list->local_idx);
	for (i = 0; i < dev_list->dev_num; i++) {
		dev = dev_list->devs[i];
		pr_device(dev);
		printf("\n");
	}
}
