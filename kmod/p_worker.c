#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/delay.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_site.h"
#include "bio_handler.h"
#include "hadm_bio.h"
#include "bwr.h"
#include "hadm_packet.h"
#include "dbm.h"
#include "utils.h"
#include "fullsync.h"
#include "hadm_thread.h"
#include "hadm_socket.h"
#include "hadm_queue.h"

#include "p_worker.h"

extern struct hadm_struct *g_hadm;

/* NOTE: 这个函数也没有处理队列被禁用的情况，因为不清除应该如何释放队列节点 */
void hadm_receive_node(int p_type, struct hdpacket *node)
{
	int dev_id;
	int handler_type;
	struct hadm_queue *queue;
	struct hadmdev *dev,*temp;
	struct hdpacket *clone_node;

	dev_id = node->head.dev_id;
	handler_type = hadmdev_packet_handler_type(p_type, &node->head);
	if (handler_type < 0) {
		pr_err("%s: can't find device handler for node(type:%d).\n",
				__FUNCTION__, node->head.type);
		return;
	}

	// FIXME read_lock? clone, push operation
	read_lock(&g_hadm->dev_list_lock);
	list_for_each_entry_safe(dev, temp, &g_hadm->dev_list, node) {
		queue = dev->queues[handler_type];
		if(dev_id == MAX_DEVICES ) {
			clone_node = hdpacket_clone(node);
			if (!clone_node)
				continue;
			clone_node->head.dev_id = dev->minor;
			hadm_queue_push(queue, &clone_node->list);
		} else if (dev_id == dev->minor) {
			hadm_queue_push(queue, &node->list);
		}
	}
	read_unlock(&g_hadm->dev_list_lock);

	if(dev_id == MAX_NODES) {
		hdpacket_free(node);
	}
}

void hadm_pack_queue_clean(struct hadm_queue *q)
{
	struct hdpacket *node;
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	if (q->len)
		pr_info("%s: try clean unempty %s queue.(remain: %d)\n",
				__FUNCTION__,
				q->name, q->len);
	while (q->len > 0) {
		node = __hadm_queue_pop_entry(q, struct hdpacket, list);
		BUG_ON(!node);
		hdpacket_free(node);
	}
	spin_unlock_irqrestore(&q->lock, flags);
}

void hadm_pack_queue_clean_for_host(struct hadm_queue *queue, struct hadm_site *host)
{
	struct hdpacket *pack_iter;
	struct hdpacket *tmp;

	spin_lock(&queue->lock);
	list_for_each_entry_safe(pack_iter, tmp, &queue->head, list) {
		if (pack_iter->head.node_from == host->id) {
			list_del_init(&pack_iter->list);
			queue->len--;
			hdpacket_free(pack_iter);
			if (waitqueue_active(&queue->push_waitqueue))
				wake_up(&queue->push_waitqueue);
		}
	}
	spin_unlock(&queue->lock);
}


#if 0
struct hdpacket *packet_node_receive(struct socket *sock, int *error)
{
	int ret;
	uint32_t vcnt;
	struct kvec *kv;
	struct hvec *hv;
	struct hdpacket *pack;
	struct packet *head;

	pack = hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack) {
		ret = -ENOMEM;
		pr_err("%s: ENOMEM.", __FUNCTION__);
		return NULL;
	}
	head = &pack->head;

	ret = hadm_socket_receive(sock, (char *)head, PACKET_HDR_LEN);
	if (ret != PACKET_HDR_LEN) {
		pr_err("%s: recevice error %d.", __FUNCTION__, ret);
		goto fail;
	}

	if (unlikely(head->magic != MAGIC)) {
		pr_err("%s: wrong packet", __FUNCTION__);
		//dump_packet("receive_node", pack);
		ret = -EINVAL;
		goto fail;
	}

	if (head->len) {
		vcnt = div_round_up(head->len, PAGE_SIZE);
		ret = hdpacket_hvmax_set(pack, vcnt);
		if (ret < 0)
			goto fail;

		kv = kzalloc(sizeof(struct kvec) * (vcnt + 1), GFP_KERNEL);
		if (!kv) {
			ret = -ENOMEM;
			goto fail;
		}
		hv = pack->hv;
		while (vcnt--) {
			kv[vcnt].iov_base = hvec_data_base(&hv[vcnt]);
			kv[vcnt].iov_len = hv[vcnt].len;
		}

		ret = hadm_socket_recvv(sock, kv, pack->hv_cnt, head->len);
		if (ret != head->len) {
			goto fail;
		}
	}

	return pack;

fail:
	if (error)
		*error = ret;
	hdpacket_free(pack);
	return NULL;
}
#endif

/* handle data/meta packet send by hadm_main server */
int p_receiver_run(int p_type)
{
	struct hadm_net *net;
	struct hadm_thread *thread;
	struct hdpacket *pack;
	char name[MAX_NAME_LEN];

	thread = g_hadm->p_receiver[p_type];
	net = find_hadm_net_by_type(p_type);
	if (!net) {
		pr_err("%s: wrong type %d.", __FUNCTION__, p_type);
		goto out;
	}
	snprintf(name, sizeof(name), "%s: ", p_type == P_CTRL_TYPE ? "CTRL" : "DATA");
	/* FIXME: can more sophisticated? what if only one link disconnect */
	while(hadm_thread_get_state(thread)==HADM_THREAD_RUN) {
		if(!hadm_socket_has_connected(net)) {
			pr_debug("%s_%s: net has not conneted.\n", __FUNCTION__, name);
			msleep(1000);
			continue;

		}

		if (get_hadm_net_socket(net) < 0) {
			dump_stack();
			continue;
		}

		while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
			pack = hdpacket_recv(net->sock);
			if (!pack) {
				pr_err("%s: receive %s data failed.\n", __FUNCTION__,
						p_type == P_CTRL_TYPE ? "CTRL":"DATA");
				break;
			}

			//dump_packet(__FUNCTION__, &pack->head);
			hadm_receive_node(p_type, pack);
		}

		hadm_net_close_socket(net);
		pr_err("%s: close %s socket: refcnt:%d\n", __FUNCTION__,
				p_type == P_CTRL_TYPE ? "CTRL":"DATA", atomic_read(&net->refcnt));
		if (net == g_hadm->ctrl_net) {
			hadm_disconnect(g_hadm);
		}
	}

out:
	complete(&thread->ev_exit);
	return 0;
}

int p_sender_run(int p_type)
{
	int ret;
	struct hadm_net *net;
	struct hadm_thread *thread;
	struct hdpacket *node;
	struct hadm_queue *queue;
	char name[MAX_NAME_LEN];

	net = find_hadm_net_by_type(p_type);
	if (IS_ERR(net)) {
		pr_err("invalid packet type:%d\n", p_type);
		return -1;
	}

	thread=g_hadm->p_sender[p_type];
	queue=g_hadm->p_sender_queue[p_type];
	snprintf(name, sizeof(name), "%s", p_type == P_CTRL_TYPE ? "CTRL" : "DATA");

	while(hadm_thread_get_state(thread)==HADM_THREAD_RUN) {
		/* 1. 检查网络是否正常 */
		if (!hadm_socket_has_connected(net)) {
			net->connect_type = (p_type==P_CTRL_TYPE)?P_KERN_HANDSHAKE_M:P_KERN_HANDSHAKE_D;
			if (hadm_net_closed(net)) {
				msleep(1000);
				continue;
			}
			if (hadm_connect_server(net) < 0) {
				pr_debug("%s_%s: connect server faild.\n", __FUNCTION__, name);
				msleep(500);
				continue;
			}
			pr_info("%s: connect to %s net success.\n", __FUNCTION__, name);
		}

		/* 2. 处理队列中的节点 */
		while(hadm_thread_get_state(thread)==HADM_THREAD_RUN) {
			node = hadm_queue_pop_entry_timeout(queue, struct hdpacket,
					list, msecs_to_jiffies(3000));
			if (IS_ERR_OR_NULL(node)) {
				if (!hadm_socket_has_connected(net))
					break;
				if (IS_ERR(node))	/* queue freezen */
					msleep(500);
				continue;
			}

			/* data_snd or ctrl_snd */
			ret = hdpacket_send(net->sock, node);
			if (ret < 0) {
				pr_err("%s: send error :%d.\n", __FUNCTION__, ret);
				break;
			}
			hdpacket_free(node);
		}

		hadm_net_close_socket(net);
		pr_err("%s: close %s socket: refcnt:%d\n", __FUNCTION__,
				p_type == P_CTRL_TYPE ? "CTRL":"DATA", atomic_read(&net->refcnt));
	}

	complete(&thread->ev_exit);
	return 0 ;
}

/* p_data/ctrl_reciver() should sheck packet type */
struct device_handler *get_worker_handler(int type)
{
	struct device_handler *handler;

	switch (type) {
	case P_SITE_CTRL:
		handler = get_site_ctrl_handler();
		break;
	case P_SITE_DATA:
		handler = get_site_data_handler();
		break;
	case P_NODE_CTRL:
		handler = get_node_ctrl_handler();
		break;
	case P_NODE_DATA:
		handler = get_node_data_handler();
		break;
	default:
		handler = NULL;
		break;
	}

	return handler;
}

int cmd_worker_run(void *arg)
{
	struct hdpacket *node;
	cmd_handler_t func;
	struct hadm_thread *thr = g_hadm->cmd_worker;
	struct hadm_queue *q = g_hadm->cmd_receiver_queue;
	struct packet_handler *handler= get_cmd_handler();

	BUG_ON(!thr || !q || !handler);

	while (hadm_thread_get_state(thr) == HADM_THREAD_RUN) {
		node = hadm_queue_pop_entry_timeout(q, struct hdpacket,
				list, msecs_to_jiffies(3000));
		if (!node)
			continue;
		if (IS_ERR(node)) {
			/* right now, means queue frozen, check later */
			msleep(3000);
			continue;
		}

		func = handler[node->head.type].func;
		if (func)
			func(node);
		hdpacket_free(node);
	}

	/* We need close/release socket, do it manual. */
	spin_lock_irq(&q->lock);
	while (q->len > 0) {
		node = __hadm_queue_pop_entry(q, struct hdpacket, list);
		hadm_socket_close(node->private);
		hadm_socket_release(node->private);
		hdpacket_free(node);
	}
	spin_unlock_irq(&q->lock);

	complete(&thr->ev_exit);
	return 0;
}

static int p_worker_run(struct hadm_queue *q, struct hadm_thread *thr,
		struct device_handler *handler, struct hadmdev *dev)
{
	device_packet_handler_t func;
	struct hdpacket *node;

	BUG_ON(!q || !thr || !handler);
	//pr_info("thread: %p(%s), queue: %p\n", thread, thread->name, queue);

	while(hadm_thread_get_state(thr)==HADM_THREAD_RUN) {
		node = hadm_queue_pop_entry_timeout(q, struct hdpacket,
				list, msecs_to_jiffies(3000));
		if (!node)
			continue;
		if (IS_ERR(node)) {
			msleep(3000);
			break;
		}

		func = handler[node->head.type].func;
		if (func)
			func(dev, node);
		hdpacket_free(node);
	}

	complete(&thr->ev_exit);
	return 0;
}

struct cmd_client {
	struct socket *sock;
	atomic_t *client_num;
	struct completion *client_ev;
};

static int __cmd_receiver(void *arg)
{
	struct cmd_client *client = (struct cmd_client *)arg;
	struct socket *sock = client->sock;
	struct hdpacket *node;
	struct hadm_queue *queue = g_hadm->cmd_receiver_queue;
	int ret;

	atomic_inc(client->client_num);

	node = hdpacket_recv(sock);
	if (IS_ERR_OR_NULL(node)) {
		hadm_socket_close(sock);
		hadm_socket_release(sock);
	} else {
		node->private = sock;
		ret = hadm_queue_push(queue, &node->list);
		if (ret == -EHADM_QUEUE_FREEZE) {
			hdpacket_free(node);
		}
	}

	complete(client->client_ev);
	atomic_dec(client->client_num);
	kfree(client);
	return 0;
}

int cmd_receiver_run(void *arg)
{
	struct hadm_thread *thread = g_hadm->p_receiver[P_CMD_TYPE];
	struct socket *sock = g_hadm->cmd_server_sock;
	struct socket *cli_sock;
	struct task_struct *task;
	int err;
	atomic_t client_num;
	struct completion client_ev;
	struct cmd_client *client;

	atomic_set(&client_num,0);
	init_completion(&client_ev);
	while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
		err = kernel_accept(sock, &cli_sock, 0);
		if (err) {
			if (err == -EINVAL) {
				pr_info("%s: sock close.\n", __FUNCTION__);
				break;
			}
			if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
				//unexcept error,
			}
			pr_info("%s: recv err :%d.\n", __FUNCTION__, err);
			continue;
		}
		client=kzalloc(sizeof(struct cmd_client),GFP_KERNEL);
		if(IS_ERR_OR_NULL(client)) {
			hadm_socket_release(cli_sock);
			continue;
		}
		client->client_num=&client_num;
		client->client_ev=&client_ev;
		client->sock=cli_sock;
		task = kthread_run(__cmd_receiver, client, "__cmd_receiver");
		if (IS_ERR(task)) {
			pr_err("cmd_receiver_run: created __cmd_receiver thread fail\n");
			kfree(client);
			hadm_socket_release(cli_sock);
		}
//		pr_info("cmd client connected and thread __cmd_receiver created.\n");
	}
	while(atomic_read(&client_num)) {
		pr_info("%s: wait for %d clients\n", __FUNCTION__,atomic_read(&client_num));
		wait_for_completion(&client_ev);

	}
	complete(&thread->ev_exit);
	return 0;
}

int cmd_sender_run(void *arg)
{
	struct hdpacket *node;
	struct socket *sock;
	struct hadm_thread *thr = g_hadm->p_sender[P_CMD_TYPE];
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CMD_TYPE];

	while(hadm_thread_get_state(thr) == HADM_THREAD_RUN) {
		node = hadm_queue_pop_entry_timeout(q, struct hdpacket,
				list, msecs_to_jiffies(3000));

		if (!node)
			continue;
		if (IS_ERR(node)) {
			/* right now, means queue frozen, check later */
			msleep(500);
			continue;
		}

		sock = node->private;
		hdpacket_send(sock, node);
		hadm_socket_close(sock);
		hadm_socket_release(sock);

		hdpacket_free(node);
	}

	// We need close/release socket, do it manual.
	spin_lock_irq(&q->lock);
	while (q->len > 0) {
		node = __hadm_queue_pop_entry(q, struct hdpacket, list);
		sock = (struct socket *)node->private;
		hadm_socket_close(sock);
		hadm_socket_release(sock);
		hdpacket_free(node);
	}
	spin_unlock_irq(&q->lock);

	complete(&thr->ev_exit);
	return 0 ;
}

int p_ctrl_sender_run(void *arg)
{
	return p_sender_run(P_CTRL_TYPE);
}

int p_data_sender_run(void *arg)
{
	return p_sender_run(P_DATA_TYPE);
}

int p_ctrl_receiver_run(void *arg)
{
	return p_receiver_run(P_CTRL_TYPE);
}

int p_data_receiver_run(void *arg)
{
	return p_receiver_run(P_DATA_TYPE);
}

int site_ctrl_worker(void *arg)
{
	struct hadmdev *dev = arg;

	return p_worker_run(dev->queues[SITE_CTRL_Q],
			dev->threads[SITE_CTRL_WORKER],
			get_site_ctrl_handler(),
			dev);
}

int site_data_worker(void *arg)
{
	struct hadmdev *dev = arg;

	return p_worker_run(dev->queues[SITE_DATA_Q],
			dev->threads[SITE_DATA_WORKER],
			get_site_data_handler(),
			dev);
}

int node_ctrl_worker(void *arg)
{
	struct hadmdev *dev = arg;

	return p_worker_run(dev->queues[NODE_CTRL_Q],
			dev->threads[NODE_CTRL_WORKER],
			get_node_ctrl_handler(),
			dev);
}

int node_data_worker(void *arg)
{
	struct hadmdev *dev = arg;

	return p_worker_run(dev->queues[NODE_DATA_Q],
			dev->threads[NODE_DATA_WORKER],
			get_node_data_handler(),
			dev);
}

int sbio_worker(void *arg)
{
	int ret;
	struct hdpacket *pack;
	struct hadmdev *dev = arg;
	struct hadm_queue *q = dev->queues[SLAVER_SBIO_Q];
	struct hadm_queue *sendq = g_hadm->p_sender_queue[P_DATA_TYPE];
	struct hadm_thread *thr = dev->threads[SLAVER_BIO_HANDLER];

	while (hadm_thread_get_state(thr) == HADM_THREAD_RUN) {
		pack = hadm_queue_pop_entry_timeout(q, struct hdpacket,
				list, msecs_to_jiffies(100));
		if (IS_ERR_OR_NULL(pack)) {
			if (IS_ERR(pack))	/* queue freezen */
				msleep(500);
			continue;
		}

		//dump_packet(__FUNCTION__, &pack->head);
		/* data_snd or ctrl_snd */
		ret = hadm_queue_push(sendq, &pack->list);
		if (ret < 0) {
			pr_err("%s: send error :%d.\n", __func__, ret);
			continue;
		}
	}

	complete(&thr->ev_exit);
	return 0;
}

#define DBM_FLUSH_INTERVAL 2000
int dbm_flusher(void *arg)
{
	int ret;
	int flushed;
	int cstate, dstate;
	struct hadmdev *dev = arg;
	struct hadm_site *runsite;
	struct hadm_thread *thr = dev->threads[DBM_FLUSH_HANDLER];

	while (hadm_thread_get_state(thr) == HADM_THREAD_RUN) {
		flushed = 0;
		list_for_each_entry(runsite, &dev->hadm_site_list, site) {
			if (runsite->id == get_site_id())
				continue;
			//pr_info("%s: store dbm for site %d.\n", __func__, runsite->id);
			//msleep(1000);
			cstate = hadm_site_get(runsite, SECONDARY_STATE, S_CSTATE);
			dstate = hadm_site_get(runsite, SECONDARY_STATE, S_DATA_STATE);
			if (cstate != C_STOPPED || dstate != DATA_DBM)
				continue;
			ret = dbm_store_async(runsite->dbm);
			if (ret < 0) {
				pr_err("%s: store dbm failed.\n", __func__);
				continue;
			} else if (ret > 0)
				flushed = 1;
		}

		//pr_info("%s finish one round flush.\n", __func__);
		//msleep(1000);
		//sync_bwr_meta(dev->bwr);
		if (flushed && !bwr_low_water(dev->bwr)) {
			continue;
		} else {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(msecs_to_jiffies(DBM_FLUSH_INTERVAL));
		}
	}

	complete(&thr->ev_exit);
	return 0;
}
