#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_node.h"
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

/* NOTE: don't use refcnt yet */
void hadm_pack_node_free(struct hadm_pack_node	*node)
{
	if (IS_ERR_OR_NULL(node)) {
		return;
	}
	if (atomic_dec_and_test(&node->refcnt)) {
		if (node->pack)
			kfree(node->pack);
		kfree(node);
	}
}

struct hadm_pack_node *hadm_pack_node_alloc(void)
{
	struct hadm_pack_node *n;

	n = kzalloc(sizeof(struct hadm_pack_node), GFP_KERNEL);

	return n;
}

void hadm_pack_node_init(struct hadm_pack_node *node,struct packet *pack,struct socket *sock)
{
	INIT_LIST_HEAD(&node->q_node);
	atomic_set(&node->refcnt, 1);
	node->pack=pack;
	node->sock=sock;
}

void hadm_pack_node_get(struct hadm_pack_node  *node)
{
	atomic_inc(&node->refcnt);
}

struct hadm_pack_node *hadm_pack_node_create(struct packet *pack,struct socket *sock)
{
	struct hadm_pack_node *node;
	node=hadm_pack_node_alloc();
	if(!IS_ERR_OR_NULL(node)){
		hadm_pack_node_init(node, pack, sock);
	}
	return node;
}

struct hadm_pack_node *hadm_pack_node_clone(struct hadm_pack_node *node,int dev_id)
{
	struct hadm_pack_node *clone_node;
	struct packet *clone_pack;
	clone_pack = packet_alloc(node->pack->len, GFP_KERNEL);
	if(IS_ERR_OR_NULL(clone_pack)) {
		return NULL;
	}
	memcpy((void *)clone_pack,(void *)node->pack,sizeof(struct packet)+node->pack->len);
	clone_pack->dev_id=dev_id;
	clone_node = hadm_pack_node_create(clone_pack,node->sock);
	if(IS_ERR_OR_NULL(clone_node)) {
		packet_free(clone_pack);
		return NULL;
	}
	return clone_node;
}

/* NOTE: 这个函数也没有处理队列被禁用的情况，因为不清除应该如何释放队列节点 */
void hadm_receive_node(int p_type,struct hadm_pack_node *node)
{
	int dev_id;
	struct hadm_queue *queue;
	struct hadmdev *dev,*temp;
	struct hadm_pack_node *clone_node;
	dev_id = node->pack->dev_id;
	read_lock(&g_hadm->dev_list_lock);
	list_for_each_entry_safe(dev,temp,&g_hadm->dev_list,node) {
		queue=dev->p_receiver_queue[p_type];
		if(dev_id == MAX_DEVICES ) {
			clone_node = hadm_pack_node_clone(node,dev->minor);
			if(IS_ERR_OR_NULL(clone_node)) {
				continue;
			}
			hadm_queue_push(queue,&clone_node->q_node);
		} else if (dev_id == dev->minor) {
			hadm_queue_push(queue,&node->q_node);
		}
	}
	read_unlock(&g_hadm->dev_list_lock);
	if(dev_id == MAX_NODES) {
		hadm_pack_node_free(node);
	}
}

uint32_t hadm_pack_queue_clean(struct hadm_queue *q)
{
	struct hadm_pack_node *node;
	unsigned long flags;
	int n = 0;

	spin_lock_irqsave(&q->lock, flags);
	while (q->len > 0) {
		node = (struct hadm_pack_node *)__hadm_queue_pop_common(q);
		hadm_pack_node_free(node);
		n++;
	}
	spin_unlock_irqrestore(&q->lock, flags);
	return n;
}

void hadm_pack_queue_clean_for_host(struct hadm_queue *queue, struct hadm_node *host)
{
	struct hadm_pack_node *pack_iter, *tmp;

	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	list_for_each_entry_safe(pack_iter, tmp, &queue->head, q_node) {
		if (pack_iter->pack->node_from == host->id || 
				(pack_iter->pack->node_to & (1<<host->id))) {
			list_del_init(&pack_iter->q_node);
			queue->len--;
			hadm_pack_node_free(pack_iter);
			if (waitqueue_active(&queue->push_waitqueue))
				wake_up(&queue->push_waitqueue);
		}
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}

int send_packet_node(struct socket *sock,struct hadm_pack_node *node)
{
	int ret = 0;
	size_t packlen=PACKET_HDR_LEN+node->pack->len;

	for (;;) {
		ret = hadm_socket_send(sock, node->pack,packlen);
		if (ret == packlen)
			break;
		if (ret == -EAGAIN) {
			pr_err("hadm_net_send: send pack(%p) again\n", node->pack);
			schedule();
			continue;
		} else if (ret < 0) {
			pr_err("hadm_net_send failed: %d\n", ret);
			return ret;
		} else if (ret != packlen) {
			pr_err("hadm_net_send failed: "
				   "send=%d, want=%lu\n", ret, packlen);
			return -EINVAL;
		}
	}
	return 0;

}

struct hadm_pack_node *packet_node_receive(struct socket *sock,int *error)
{
	struct hadm_pack_node *node=NULL;
	struct packet *pack=NULL,*data_pack=NULL;
	size_t packlen;
	int ret=0;
	*error=0;
	packlen=PACKET_HDR_LEN;
	pack=kzalloc(packlen,GFP_KERNEL);
	if(IS_ERR_OR_NULL(pack)){
		*error=-ENOMEM;
		return NULL;
	}
	ret=hadm_socket_receive(sock,(char *)pack,packlen);
#if 0
	if(sock != g_hadm->ctrl_net->sock && sock != g_hadm->data_net->sock) {
		pr_info("hadm_socket_receive complete, ret=%d\n",ret);
	}
#endif
	if(ret != packlen) {
		*error=ret;
		goto recv_done;
	}
	if (pack->magic != MAGIC) {
		pr_err("ctrl_client_receive_node: wrong packet\n");
		//dump_packet("receive_node", pack);
		*error=-EINVAL;
		goto recv_done;
	}

	if(pack->len>0) {
		packlen = PACKET_HDR_LEN + pack->len;
		data_pack = kzalloc(packlen, GFP_KERNEL);
		if(IS_ERR_OR_NULL(data_pack)) {
			*error = -ENOMEM;
			goto recv_done;
		}
		memcpy(data_pack, pack, PACKET_HDR_LEN);
		ret = hadm_socket_receive(sock, (char *)data_pack->data, data_pack->len);
		if(ret==data_pack->len){
			kfree(pack);
			pack = data_pack;
		}
		else {
			kfree(data_pack);
			if(ret<0) {
				*error = ret;
			}
			else {
				*error=-ENOTCONN;
			}
			goto recv_done;
		}
	}
	node = hadm_pack_node_create(pack,sock);
	if(IS_ERR_OR_NULL(node)) {
		*error=-ENOMEM;
		goto  recv_done;
	}

recv_done:
	if(*error){
		if(pack)
			kfree(pack);
		if(node)
			kfree(node);
		return NULL;
	}
	return node;
}

int p_receiver_run(int p_type)
{
	struct hadm_net *net;
	struct hadmdev *dev;
	struct hadm_node *hadm_node;
	struct hadm_thread *thread;
	struct hadm_pack_node *node;
	int error=0;

	net = find_hadm_net_by_type(p_type);
	thread=g_hadm->p_receiver[p_type];
	while(hadm_thread_get_state(thread) == HADM_THREAD_RUN && !hadm_net_closed(net)) {
		if(!hadm_net_connected(net)) {
			msleep(1000);
			continue;

		}
		if (get_hadm_net_socket(net) < 0) {
			dump_stack();
			continue;
		}

		while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
			node = packet_node_receive(net->sock, &error);
			if (node) {
				hadm_receive_node(p_type, node);
			} else {
				if(hadm_net_closed(net)) {
					break;
				}
				if(error != -EAGAIN && error != -EINTR &&
						error != -ERESTARTSYS) {
					pr_err("receive %s data failed,error:%d\n",
							(p_type==P_CTRL_TYPE)?"CTRL":"DATA",
							error);

					break;
				}
			}
		}
//		pr_info("close socket net %p , state = %d,  socket = %p, refcnt = %d\n", 
//				net, net->cstate, net->sock, atomic_read(&net->refcnt));
		hadm_net_close_socket(net);
//		pr_info("socket net %p closed, state = %d,  socket = %p, refcnt = %d\n", 
//				net, net->cstate, net->sock, atomic_read(&net->refcnt));
		if (net == g_hadm->ctrl_net) {
			list_for_each_entry(dev, &g_hadm->dev_list, node) {
				list_for_each_entry(hadm_node, &dev->hadm_node_list, node)
					disconnect_node(hadm_node);
			}
		}
	}

	hadm_thread_terminate(thread);
	//complete(&thread->ev_exit);
	return 0;
}
/**
 *因为__p_fullsync_md5的io是异步实现的，无法在endio回调中计算md5,所以
 *在endio里将读到的内容写入到packet->data中，将原始包的md5写到pack->md5里
 *在发送之前比较md5的值，得到errcode
 */
static void packet_pre_send(struct hadm_pack_node *node)
{
	char md5[16];
	if(node->pack->type == P_FULLSYNC_DATA_REQ) {
		fullsync_md5_hash(node->pack->data, PAGE_SIZE, md5);
		node->pack->errcode = memcmp(md5, node->pack->md5, 16) ? -FULLSYNC_DATA_REQ : 0;
		node->pack->len = 0 ;
	}
}

int p_cmd_sender_run(void)
{
	struct hadm_thread *thread;
	struct hadm_pack_node *node;
	struct hadm_queue *queue;


	thread = g_hadm->p_sender[P_CMD_TYPE];
	queue = g_hadm->cmd_sender_queue;

	while(hadm_thread_get_state(thread)==HADM_THREAD_RUN) {
		node = (struct hadm_pack_node *)hadm_queue_pop_timeout(queue,
				msecs_to_jiffies(1000));
		if(IS_ERR_OR_NULL(node))
			continue;
		send_packet_node(node->sock, node);
		hadm_socket_close(node->sock);
		hadm_socket_release(node->sock);
		hadm_pack_node_free(node);
	}
	spin_lock_irq(&queue->lock);
	while (queue->len > 0) {
		node = (struct hadm_pack_node *)__hadm_queue_pop_common(queue);
		hadm_socket_close(node->sock);
		hadm_socket_release(node->sock);
		hadm_pack_node_free(node);
	}
	spin_unlock_irq(&queue->lock);
	hadm_thread_terminate(thread);
	return 0;
}

int p_sender_run(int p_type)
{
	int ret;
	struct hadm_net *net;
	struct hadm_thread *thread;
	struct hadm_pack_node *node;
	struct hadm_queue *queue, *tmp_queue;
	struct hadmdev *dev;
	unsigned long flags;

	net = find_hadm_net_by_type(p_type);
	if (IS_ERR(net)) {
		pr_err("invalid packet type:%d\n", p_type);
		return -1;
	}
	tmp_queue = hadm_queue_create("send_tmp_queue", MAX_QUEUE_LEN);
	if(IS_ERR_OR_NULL(tmp_queue)){
		return -1;
	}

	thread=g_hadm->p_sender[p_type];

	while(hadm_thread_get_state(thread)==HADM_THREAD_RUN) {

		/* 1. 检查网络是否正常 */
		if(hadm_net_closed(net)) {
			break;
		}
		if (!hadm_net_connected(net)) {
			wake_up(&g_hadm->queue_event);
			net->connect_type = (p_type == P_CTRL_TYPE)?
				P_KERN_HANDSHAKE_M : P_KERN_HANDSHAKE_D;
			if (hadm_connect_server(net) < 0) {
				msleep(1500);
				continue;
			}
		}

		/* 2. 处理队列中的节点 */

		while(hadm_thread_get_state(thread)==HADM_THREAD_RUN) {
			if (net && !hadm_net_connected(net)) {
				break;
			}
			if(wait_event_timeout(g_hadm->queue_event, 
					atomic_read(&(g_hadm->sender_queue_size[p_type])) > 0,
					msecs_to_jiffies(3000)) == 0)
				continue;
			read_lock_irqsave(&g_hadm->dev_list_lock, flags);
			list_for_each_entry(dev, &g_hadm->dev_list, node) {
				queue = dev->p_sender_queue[p_type];
				node = (struct hadm_pack_node *)hadm_queue_pop_nowait(queue);
				if(IS_ERR_OR_NULL(node))
					continue;
				hadm_queue_push(tmp_queue, &node->q_node);
			}
			read_unlock_irqrestore(&g_hadm->dev_list_lock, flags);
			ret = 0;
			while((node = (struct hadm_pack_node *)hadm_queue_pop_nowait(tmp_queue)) != NULL) {
				packet_pre_send(node);
				ret = send_packet_node(net->sock, node);
				hadm_pack_node_free(node);
				if(ret < 0) 
					break;
				atomic_dec(&g_hadm->sender_queue_size[p_type]);
				wake_up(&g_hadm->queue_event);
			}
			if(ret < 0) {
				break;
			}
		}
		hadm_net_close_socket(net);

	}
	hadm_pack_queue_clean(tmp_queue);
	hadm_queue_free(tmp_queue);
	hadm_thread_terminate(thread);
	//complete(&thread->ev_exit);
	return 0 ;
}

packet_handler_t get_worker_functions(int p_type,int pack)
{
	switch(p_type){
		case P_CTRL_TYPE:return get_ctrl_worker_handler(pack);
		case P_DATA_TYPE:return get_data_worker_handler(pack);
		case P_CMD_TYPE:return get_cmd_worker_handler(pack);
		default:return NULL;
	}
	return NULL;
}

static int p_worker_run(int p_type,struct hadmdev *hadmdev)
{
	struct hadm_thread *thread;
	struct hadm_pack_node *node;
	struct hadm_queue *queue;
	packet_handler_t func;

	switch(p_type) {
		case P_CTRL_TYPE:
			thread=hadmdev->worker_thread[p_type];
			queue=hadmdev->p_receiver_queue[p_type];
			break;
		case P_DATA_TYPE:
			thread=hadmdev->worker_thread[p_type];
			queue=hadmdev->p_receiver_queue[p_type];
			break;
		case P_CMD_TYPE:
			thread = g_hadm->cmd_worker;
			queue = g_hadm->cmd_receiver_queue;
			break;
		default:
			pr_err("invalid packet type:%d\n",p_type);
			return -1;
	}

	//pr_info("thread: %p(%s), queue: %p\n", thread, thread->name, queue);

	while(hadm_thread_get_state(thread)==HADM_THREAD_RUN) {
		for (;;) {
			node = (struct hadm_pack_node *)hadm_queue_pop_timeout(queue, msecs_to_jiffies(3000));
			if (IS_ERR(node)) {
				schedule();
				break;
			} else if (node == NULL) { /* timeout */
				continue;
			}
//			dump_packet(__FUNCTION__, node->pack);
//			if(p_type == P_DATA_TYPE)
//				dump_packet("", node->pack);
			func = get_worker_functions(p_type, node->pack->type);
			if (func)
				func(node);
			hadm_pack_node_free(node);
		}
	}

	if (p_type == P_CMD_TYPE) {
		/* We need close/release socket, do it manual. */
		spin_lock_irq(&queue->lock);
		while (queue->len > 0) {
			node = (struct hadm_pack_node *)__hadm_queue_pop_common(queue);
			hadm_socket_close(node->sock);
			hadm_socket_release(node->sock);
			hadm_pack_node_free(node);
		}
		spin_unlock_irq(&queue->lock);
	}

	hadm_thread_terminate(thread);
	//complete(&thread->ev_exit);
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
	struct hadm_pack_node *node;
	struct hadm_queue *queue = g_hadm->cmd_receiver_queue;
	int ret, error;

	atomic_inc(client->client_num);

	node=packet_node_receive(sock,&error);
	if (IS_ERR_OR_NULL(node)) {
		//TODO: WARNING
		hadm_socket_close(sock);
		hadm_socket_release(sock);
	} else {
		ret = hadm_queue_push(queue, &node->q_node);
		if(ret) {
			pr_warn("%s :push data to cmd receiver queue failed\n", __FUNCTION__);
		}
		if (ret == -EHADM_QUEUE_FREEZE) {
			hadm_pack_node_free(node);
		}
	}

	atomic_dec(client->client_num);

	complete(client->client_ev);
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
			if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
				//unexcept error,
			}
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
	hadm_thread_terminate(thread);
	return 0;
}

int cmd_sender_run(void *arg)
{
	return p_cmd_sender_run();
}

int cmd_worker_run(void *arg)
{
	return p_worker_run(P_CMD_TYPE,NULL);
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

int p_ctrl_worker_run(void *arg)
{
	return p_worker_run(P_CTRL_TYPE,(struct hadmdev *)arg);
}

int p_data_worker_run(void *arg)
{
	return p_worker_run(P_DATA_TYPE,(struct hadmdev *)arg);
}
