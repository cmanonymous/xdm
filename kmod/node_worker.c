#define pr_fmt(fmt) "node_worker: " fmt

#include "p_worker.h"
#include "hadm_node.h"
#include "hadm_device.h"
#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_bio.h"


static int __p_node_connect(struct hadmdev *dev, struct hadm_node *node)
{
	if (!hadmdev_get_master(dev))
		hadmdev_send_node_state_request(dev, NULL);

	if (hadm_node_connect(node))
		return 0;

	pr_info("%s: node(%s) %d connect!\n", __FUNCTION__,
			node->name,
			node->id);
	hadmdev_node_connect(dev, node);

	return 0;
}

static int __p_node_disconnect(struct hadmdev *dev, struct hadm_node *node)
{
	if (!hadm_node_connect(node))
		return 0;

	pr_info("%s: node(%s) %d disconnect!\n", __FUNCTION__,
			node->name,
			node->id);

	hadmdev_node_disconnect(dev, node);

	return 0;
}

static int p_node_conn_state(struct hadmdev *dev, struct hdpacket *pack)
{
	int nstate;
	int local_node_id;
	struct hadm_node *node;
	struct packet *head = &pack->head;

	local_node_id = get_node_id();
	//pr_info("%s recv node_to:%u.\n", __FUNCTION__, pack->node_to);
	list_for_each_entry(node, &dev->hadm_node_list, node) {
		if (node->id == local_node_id)
			continue;
		nstate = ((1 << node->id) & head->node_to) ?
			N_CONNECT : N_DISCONNECT;
		if (nstate == N_DISCONNECT)
			__p_node_disconnect(dev, node);
		else
			__p_node_connect(dev, node);
	}

	return 0;
}

static int p_node_master(struct hadmdev *dev, struct hdpacket *pack)
{
	int ret = 0;
	struct packet *head = &pack->head;
	struct hadm_node *node;

	pr_info("%s recv master notify from %d\n", __FUNCTION__, head->node_from);

	spin_lock(&dev->master_lock);
	if (dev->master) {
		pr_err("%s multi-master detected! prev:%s(%d), request:%d.\n",
				__FUNCTION__, dev->master->name,
				dev->master->id, head->node_from);
		ret = -EKMOD_UNKNOWN_STATE;
		goto out;
	}

	node = hadmdev_node_find(dev, head->node_from);
	if (!node) {
		pr_err("%s can not find source node(%d).\n",
				__FUNCTION__, head->node_from);
		ret = -EKMOD_NONODE;
		goto out;
	}

	pr_info("%s set master to %s(%d).\n", __FUNCTION__,
			node->name, node->id);
	dev->master = node;

out:
	spin_unlock(&dev->master_lock);
	return ret;
}

static int p_node_state_request(struct hadmdev *dev, struct hdpacket *pack)
{
	struct hadm_node *node;
	struct packet *head = &pack->head;

	if (!hadmdev_local_master(dev))
		return 0;

	node = hadmdev_node_find(dev, head->node_from);
	if (!node) {
		pr_err("%s: can not find peer node(%d).\n",
				__FUNCTION__, head->node_from);
		return -EKMOD_NONODE;
	}

	return hadmdev_send_node_state(dev, node);
}

static int p_node_state(struct hadmdev *dev, struct hdpacket *pack)
{
	int ret = 0;
	struct hadm_node *node;
	struct packet *head = &pack->head;

	pr_info("%s: node state %d(P)|%d(M)|%d(O).\n",
			__func__, head->primary, head->master, head->open);
	node = hadmdev_node_find(dev, head->node_from);
	if (!node) {
		pr_err("%s: can not find peer node(%d).\n",
				__FUNCTION__, head->node_from);
		ret = -EKMOD_NONODE;
		goto out;
	}

	if (hadmdev_local_master(dev)) {
		/* master节点获取slaver节点信息 */

		/* slaver节点是否有打开设备 */
		if (head->open) {
			pr_info("%s: set node%d open.\n", __func__, node->id);
			set_hadm_node_open(node);
		} else {
			pr_info("%s: clear node%d open.\n", __func__, node->id);
			clear_hadm_node_open(node);
		}
	} else {
		/* slaver节点获取master节点信息 */

		if (head->primary) {
			if (hadmdev_get_primary_id(dev) == INVALID_ID) {
				ret = hadmdev_do_slaver_primary(dev);
				if (ret < 0)
					goto out;
			}
		} else {
			if (hadmdev_local_primary(dev)) {
				pr_info("%s: clear slaver primary.\n", __FUNCTION__);
				ret = hadmdev_do_slaver_secondary(dev);
				if (ret < 0)
					goto out;
			}
		}

		node = head->master ? node : NULL;
		ret = hadmdev_set_slaver_master(dev, node);
	}

out:
	return ret;
}

static int p_node_sbio(struct hadmdev *dev, struct hdpacket *pack)
{
	int err;
	struct packet *head = &pack->head;
	struct packet *rhead;
	struct bio_wrapper *wrapper;
	struct hadm_queue *wrapper_queue;
	struct hdpacket *reply;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	//dump_packet(__FUNCTION__, head);
	//pr_info("%s: bio->bi_sector:%llu|bio->bi_flags:%llu|rw:%llu|size:%u\n",
			//__func__,
			//head->dev_sector,
			//head->bi_flags,
			//head->bi_rw,
			//head->bi_size);

	/* 对于读请求，读出来的数据希望放到reply中，reply包在这里已经初始化完成，
	 * 对于写请求，我们需要保留数据，而在写完成后再释放掉数据，需要重新初始化
	 * reply包.
	 */

	err = -ENOMEM;
	if (head->bi_rw & WRITE)
		reply = hdpacket_clone(pack);
	else
		/* check head->bi_size in remote_wrapper_split() */
		reply = node_hdpacket_alloc(GFP_KERNEL,
				div_round_up(head->bi_size, PAGE_SIZE), HADM_DATA_PAGE);
	if (!reply) {
		pr_err("%s: alloc reply pack failed, remote io lose reponse.\n",
				__func__);
		goto error;
	}
	rhead = &reply->head;
	rhead->type = P_ND_SBIO_ACK;
	rhead->node_to = (1 << head->node_from);
	rhead->dev_sector = head->dev_sector;
	rhead->bi_rw = head->bi_rw;
	rhead->bi_size = head->bi_size;
	rhead->bi_flags = head->bi_flags;

	wrapper = hadmdev_create_remote_wrapper(dev, reply);
	if (!wrapper) {
		pr_err("%s: wrapper create faild.\n", __FUNCTION__);
		goto response;
	}

	if (pack->head.bi_rw & WRITE)
		wrapper_queue = dev->queues[WR_WRAPPER_Q];
	else
		wrapper_queue = dev->queues[RD_WRAPPER_Q];
	err = hadm_queue_push(wrapper_queue, &wrapper->node);
	if (err < 0) {
		pr_err("%s: push wrapper failed.\n", __FUNCTION__);
		free_bio_wrapper(wrapper);
		goto response;
	}

	return 0;

response:
	reply->head.errcode = err;
	err = hadm_queue_push(q, &reply->list);
	if (err < 0) {
		pr_err("%s: push err response failed.(%d)\n", __FUNCTION__, err);
		hdpacket_free(reply);
	}
error:
	return err;
}

static int p_node_sbio_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	int i;
	int err = 0;
	struct sbio *sbio;
	struct bio *bio;
	struct hadm_io *hv;
	struct bio_vec *iov;
	struct packet *head = &pack->head;
	struct hdpack_data *data = pack->data;

	//dump_packet(__func__, &pack->head);
	//dump_hdpack_data(__func__, data);

	sbio = hadmdev_sbio_search_pop(dev, head->dev_sector);
	if (!sbio) {
		pr_err("%s: no such sbio.%llu.\n", __FUNCTION__, head->dev_sector);
		err = -1;
		goto out;
	}

	if (head->errcode) {
		err = -EIO;
		goto endio;
	}

	bio = sbio->bio;
	if (head->bi_rw & WRITE) {
		//pr_info("%s: write reply, don't implement yet.\n", __func__);
		//err = -EIO;
	} else {
		/* for read bio, we need copy the data
		 * we make sure bio->bi_size is multip of PAGE_SIZE,
		 * but, how about each iov?
		 */
		if (head->len != bio->bi_size ||
				data->vcnt != bio->bi_vcnt) {
			pr_err("%s: not equal size(%d:%d)|vcnt(%d:%d)\n",
					__func__,
					head->len, bio->bi_size,
					data->vcnt, bio->bi_vcnt);
			err = -EIO;
			goto endio;
		}
		for (i = 0; i < bio->bi_vcnt; i++) {
			hv = &data->hv[i];
			iov = &bio->bi_io_vec[i];

			/* FIXME: perharps we need manual copy */
			BUG_ON(iov->bv_len != hv->len);
#if 0
			if (iov->bv_len != PAGE_SIZE) {
				pr_err("%s: unsupport bvec size.%d\n",
						__func__, iov->bv_len);
				err = -EIO;
				goto endio;
			}
#endif
			memcpy(page_address(iov->bv_page) + iov->bv_offset,
					page_address(hv->page) + hv->start,
					hv->len);
		}
	}

endio:
	bio_endio(sbio->bio, err);
	sbio_free(sbio);
out:
	return err;
}

struct device_handler node_handler[] = {
	[P_NC_CONN_STATE] = { p_node_conn_state},
	[P_NC_MASTER] = { p_node_master},
	[P_NC_STATE_REQ] = { p_node_state_request},
	[P_NC_STATE] = { p_node_state},
	[P_ND_SBIO] = { p_node_sbio},
	[P_ND_SBIO_ACK] = { p_node_sbio_ack},
};

struct device_handler node_data_handler[] = {
};

struct device_handler *get_node_ctrl_handler()
{
	return node_handler;
}

struct device_handler *get_node_data_handler()
{
	return node_handler;
}
