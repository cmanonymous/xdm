#include <linux/module.h>
#include <linux/slab.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_config.h"
#include "hadm_node.h"
#include "hadm_device.h"
#include "dbm.h"
#include "buffer.h"
#include "bwr.h"
#include "p_worker.h"

#define NOT_USE_PACKET_NAME
#define NOT_USE_PROTO_NAME
#include "../include/common_string.h"

extern struct hadm_struct *g_hadm;

//FIXME lock?
struct hadm_node *find_hadm_node_by_id(struct hadmdev *dev, uint32_t node_id)
{
	struct hadm_node *hadm_node;

	list_for_each_entry(hadm_node, &dev->hadm_node_list, node) {
		if (hadm_node->id == node_id)
			return hadm_node;
	}

	return NULL;
}

struct node_state_packet *node_state_packet_entry(struct packet *pack,
						  uint32_t node_id)
{
	struct node_state_packet *ns_pack;
	int i;

	ns_pack = (struct node_state_packet *)pack->data;
	for (i = 0; i < pack->node_state_num; i++) {
		if (ns_pack->id == node_id)
			return ns_pack;
		ns_pack += 1;
	}

	return NULL;
}

void hadm_node_conf_free(struct hadm_node_conf *conf)
{
	kfree(conf);
}

struct hadm_node_conf *hadm_node_conf_alloc(void)
{
	struct hadm_node_conf *conf;

	conf = kzalloc(sizeof(struct hadm_node_conf), GFP_KERNEL);

	return conf;
}

void hadm_node_conf_init(struct hadm_node_conf *conf,
			 uint8_t protocol, char *hostname, char *ipaddr,
			 char *disk, char *bwr_disk)
{
	conf->protocol = protocol;
	snprintf(conf->hostname, MAX_NAME_LEN, "%s", hostname);
	snprintf(conf->ipaddr, MAX_IPADDR_LEN, "%s", ipaddr);
	snprintf(conf->disk, MAX_NAME_LEN, "%s", disk);
	snprintf(conf->bwr_disk, MAX_NAME_LEN, "%s", bwr_disk);
}

struct hadm_node_conf *hadm_node_conf_create(uint8_t protocol,
					     char *hostname, char *ipaddr,
					     char *disk, char *bwr_disk)
{
	struct hadm_node_conf *conf;

	conf = hadm_node_conf_alloc();
	if (conf)
		hadm_node_conf_init(conf, protocol, hostname, ipaddr, disk, bwr_disk);

	return conf;
}

void hadm_node_state_dump(struct hadm_node_state *state)
{
	pr_info("++++++++ %s ++++++++\n", __FUNCTION__);
	pr_info("%d|%s|%s|%s|%s|%s\n",
		state->node->id,
		role_name[state->role],
		dev_state_name[state->dev_state],
		cstate_name[state->c_state],
		dstate_name[state->d_state],
		nstate_name[state->n_state]);
	pr_info("-------- %s --------\n", __FUNCTION__);
}

void hadm_node_state_free(struct hadm_node_state *state)
{
	if (state != NULL && !IS_ERR(state)) {
		if (state->snd_head_data)
			bwr_data_put(state->snd_head_data);
		kfree(state);
	}
}

struct hadm_node_state *hadm_node_state_alloc(int gfp_mask)
{
	struct hadm_node_state *state;

	state = kzalloc(sizeof(*state), gfp_mask);
	if (state == NULL) {
		pr_err("hadm_node_state_alloc: no memory\n");
		return ERR_PTR(-ENOMEM);
	}

	return state;
}

void hadm_node_state_init(struct hadm_node_state *state)
{
	spin_lock_init(&state->lock);
	state->role = R_SECONDARY;
	state->dev_state = DEV_DOWN;
	state->handshake = HS_FAIL;

	state->data_state = DATA_CONSISTENT;
	state->c_state = C_STOPPED;
	state->d_state = D_CONSISTENT;
	state->n_state = N_DISCONNECT;

	state->invalid = 1;
}

/* 都没加锁，允许读到过时的信息吗？如果允许，那么对于head > tail等情况也要在显示的时候加以注意 */
void hadm_node_state_pack(struct node_state_packet *ns_pack, struct hadm_node_state *state)
{
	struct bwr* bwr = state->node->hadmdev->bwr;
	int primary_id, local_node_id;

	local_node_id = get_node_id();
	primary_id = hadmdev_get_primary_id(state->node->hadmdev);

	ns_pack->id = state->node->id;
	ns_pack->role = state->role;
	ns_pack->kmod_id = state->node->kmod_id;
	ns_pack->protocol = state->node->conf.real_protocol;

	ns_pack->dev_state = state->dev_state;
	ns_pack->data_state = state->data_state;
	ns_pack->c_state = state->c_state;
	ns_pack->n_state = state->n_state;

	ns_pack->snd_head = state->snd_head;
	ns_pack->snd_ack_head = state->snd_ack_head;
	if (ns_pack->id == local_node_id) {
		ns_pack->disk_state = bwr->mem_meta.disk_state;
		ns_pack->dbm_set = state->dbm_set;
	} else
		ns_pack->dbm_set = atomic_read(&state->node->dbm->nr_bit);

	/* accepted primary */
	if (primary_id != INVALID_ID && primary_id != local_node_id) {
		ns_pack->node_head = state->node_head;
		ns_pack->tail = state->tail;
	} else {
		ns_pack->node_head = bwr->mem_meta.head[ns_pack->id];
		ns_pack->tail = bwr->mem_meta.tail;
	}
}

void hadm_node_state_unpack(struct hadm_node_state *state, struct node_state_packet *ns_pack)
{
	state->node->id = ns_pack->id;
	state->role = ns_pack->role;
	state->node->conf.real_protocol = ns_pack->protocol;

	state->dev_state = ns_pack->dev_state;
	state->data_state = ns_pack->data_state;
	state->c_state = ns_pack->c_state;
	state->n_state = ns_pack->n_state;

	state->node_head = ns_pack->node_head;
	state->snd_head = ns_pack->snd_head;
	state->tail = ns_pack->tail;

	/* NOTE: how to set node_head/tail? */
	state->dbm_set = ns_pack->dbm_set;
}

int hadm_node_next_cstate(struct hadm_node *node)
{
	return 0;
}

void hadm_node_become_inconsitent(struct hadm_node *node)
{
	unsigned long flags, flags2;
	if(hadm_thread_get_state(node->delta_sync) == HADM_THREAD_RUN){
		pr_info("hadm%d bwr is full , stop node %d delta_sync thread \n",
				node->hadmdev->minor, node->id);
		hadm_thread_stop(node->delta_sync);
		hadm_thread_join(node->delta_sync);
		hadm_thread_free(&node->delta_sync);
	}
	/**
	 *这里主要是把C_STATE设置为C_STOPPED，以保证sync dbm能够执行
	 */
	spin_lock_irqsave(&node->s_state.lock, flags);
	if(__hadm_node_get(&node->s_state, S_CSTATE) != C_STOPPED ||
			__hadm_node_get(&node->s_state, S_DSTATE) != D_INCONSISTENT) {
		if(__hadm_node_get(&node->s_state, S_DATA_STATE) == DATA_CONSISTENT) {
			__hadm_node_set(&node->s_state, S_DATA_STATE, DATA_DBM);
		}
		__hadm_node_set(&node->s_state, S_CSTATE, C_STOPPED);
		__hadm_node_set(&node->s_state, S_DSTATE, D_INCONSISTENT);
		write_lock_irqsave(&node->hadmdev->bwr->lock, flags2);
		__hadm_node_reset_send_head(node); /* atomic reset & set DATA_DBM */
		write_unlock_irqrestore(&node->hadmdev->bwr->lock, flags2);
	}

	pr_info("hadm%d after set state node:%d, cstate:%d, dstate:%d, snd_head:%llu\n",
			node->hadmdev->minor, node->id,
			(int)__hadm_node_get(&node->s_state, S_CSTATE),
			(int)__hadm_node_get(&node->s_state, S_DSTATE),
			__hadm_node_get(&node->s_state, S_SND_HEAD)
			);

	spin_unlock_irqrestore(&node->s_state.lock, flags);
}

void hadm_node_free(struct hadm_node *node)
{
	if (node == NULL || IS_ERR(node))
		return;
	if (node->id != get_node_id())
		free_dbm(node->dbm);
	kfree(node);
}

struct hadm_node *hadm_node_alloc(int gfp_mask)
{
	struct hadm_node *node;

	node = kzalloc(sizeof(*node), gfp_mask);

	return node;
}

static void hadm_node_init(struct hadm_node *node, struct hadmdev *dev,
		    uint32_t node_id, uint32_t kmod_id, uint8_t protocol)
{
	node->hadmdev = dev;
	node->id = node_id;
	node->kmod_id = kmod_id;
	//snprintf(node->dbm_name, MAX_NAME_LEN, "%s", dbm);

	node->conf.protocol = protocol;
	node->conf.real_protocol = PROTO_ASYNC;
	pr_info("hadm%d init node %d, protocol:%u, real_protocol:%u.\n",
			node->hadmdev->minor, node->id, 
			node->conf.protocol, node->conf.real_protocol);
	//snprintf(node->conf.disk, MAX_NAME_LEN, "%s", disk_name);
	//snprintf(node->conf.bwr_disk, MAX_NAME_LEN, "%s", bwr_name);

	INIT_LIST_HEAD(&node->node);
	node->s_state.node = node;
	node->p_state.node = node;
	hadm_node_state_init(&node->s_state);
	hadm_node_state_init(&node->p_state);
	node->delta_sync=NULL;
}

struct hadm_node *hadm_node_create(struct hadmdev *dev, uint32_t node_id,
				   uint32_t kmod_id, uint8_t protocol)
{
	struct hadm_node *node;

	node = hadm_node_alloc(GFP_KERNEL);
	if (node != NULL)
		hadm_node_init(node, dev, node_id, kmod_id, protocol);

	return node;
}

void cstate_debug(struct hadm_node_state *state, int cstate_old, int cstate_new)
{
	if (cstate_old != cstate_new) {
		pr_info("hadm %d node %d cstate change(%s -> %s)\n",
				state->node->hadmdev->minor, 
				state->node->id, 
				cstate_name[cstate_old], cstate_name[cstate_new]);
		/* dump_stack(); */
	}
}

void __hadm_node_set(struct hadm_node_state *state, int field, int val)
{
	switch (field) {
	case S_INVALID:
		state->invalid = val;
		break;
	case S_HANDSHAKE:
		state->handshake = val;
		break;
	case S_DSTATE:
		state->d_state = val;
		break;
	case S_DEV_STATE:
		state->dev_state = val;
		break;
	case S_ROLE:
		state->role = val;
		break;
	case S_CSTATE:
		cstate_debug(state, state->c_state, val);
		state->c_state = val;
		break;
	case S_NSTATE:
		state->n_state = val;
		break;
	case S_BWR_SIZE:
		state->bwr_size = val;
		break;
	case S_SND_HEAD:
		state->snd_head = val;
		break;
	case S_DATA_STATE:
		state->data_state = val;
		break;
	default:
		break;
	}
}

void hadm_node_set(struct hadm_node *node, int which, int field, int val)
{
	struct hadm_node_state *state;
	unsigned long flags;

	state = (which == PRIMARY_STATE) ? &node->p_state : &node->s_state;
	if(IS_ERR_OR_NULL(state)) {
		BUG();
	}

	spin_lock_irqsave(&state->lock, flags);
	__hadm_node_set(state, field, val);
	spin_unlock_irqrestore(&state->lock, flags);
}

int __hadm_node_test_and_set(struct hadm_node_state *state, int field, int test_val, int val)
{
	int ret = 0, *field_val = NULL;

	switch (field) {
	case S_HANDSHAKE:
		field_val = &state->handshake;
		break;
	case S_CSTATE:
		field_val = &state->c_state;
		break;
	case S_DATA_STATE:
		field_val = &state->data_state;
		break;
	case S_DSTATE:
		field_val = &state->d_state;
		break;
	case S_NSTATE:
		field_val = &state->n_state;
		break;
	case S_ROLE:
		field_val = &state->role;
		break;
	case S_DEV_STATE:
		field_val = &state->dev_state;
		break;
	default:
		pr_warning("no field %d\n", field);
		break;
	}

	if (field_val && *field_val == test_val) {
		*field_val = val;
		ret = 1;
	}

	return ret;
}

int hadm_node_test_and_set(struct hadm_node *node, int which, int field, int test_val, int val)
{
	int ret = 0;
	unsigned long flags;
	struct hadm_node_state *state;

	state = (which == PRIMARY_STATE) ? &node->p_state : &node->s_state;

	spin_lock_irqsave(&state->lock, flags);
	__hadm_node_test_and_set(state, field, test_val, val);
	spin_unlock_irqrestore(&state->lock, flags);

	return ret;
}

uint64_t __hadm_node_get(struct hadm_node_state *state, int field)
{
	int val = 0;

	switch (field) {
	case S_INVALID:
		val = state->invalid;
		break;
	case S_HANDSHAKE:
		val = state->handshake;
		break;
	case S_DEV_STATE:
		val = state->dev_state;
		break;
	case S_ROLE:
		val = state->role;
		break;
	case S_CSTATE:
		val = state->c_state;
		break;
	case S_DSTATE:
		val = state->d_state;
		break;
	case S_DATA_STATE:
		val = state->data_state;
		break;
	case S_NSTATE:
		val = state->n_state;
		break;
	case S_BWR_SIZE:
		val = state->bwr_size;
		break;
	case S_SND_HEAD:
		val = state->snd_head;
		break;
	default:
		val = 0;
		break;
	}

	return val;
}

uint64_t hadm_node_get(struct hadm_node *node, int which, int field)
{
	struct hadm_node_state *state;
	unsigned long flags;
	int val = 0;

	state = (which == PRIMARY_STATE) ? &node->p_state : &node->s_state;

	spin_lock_irqsave(&state->lock, flags);
	val = __hadm_node_get(state, field);
	spin_unlock_irqrestore(&state->lock, flags);

	return val;
}

int hadm_node_bit_to_num(uint32_t node_id)
{
	int i;

	for (i = 0; i < MAX_NODES; i++) {
		if (node_id == (1<<i))
			return i;
	}

	return -1;
}

void hadm_node_net_head_inc(struct hadm_node *node, sector_t bwr_sector, sector_t bwr_seq)
{
	unsigned long flags;
	struct hadm_queue *queue = node->hadmdev->bio_wrapper_queue[HADM_IO_WRITE];
	struct data_buffer *buffer = node->hadmdev->buffer;
	struct bwr_data *entry;
	struct bio_wrapper *bio_wrapper ;
	uint64_t prev_seq;
	int founded = 0;
	/**FIXME set node protocol to SYNC when tail = snd_ack_head **/
	spin_lock_irqsave(&node->s_state.lock, flags);
	if(node->s_state.snd_ack_head != bwr_sector) {
		pr_warning("%s:hadm%d unexcept net ack packet for node %d, snd_ack_head = %llu, packet bwr_sector = %llu\n",
				__FUNCTION__, node->hadmdev->minor,
				node->id,
				(unsigned long long)node->s_state.snd_ack_head,
				(unsigned long long)bwr_sector);
		spin_unlock_irqrestore(&node->s_state.lock, flags);
		return;
	}else {
		node->s_state.snd_ack_head = bwr_next_sector(node->hadmdev->bwr, node->s_state.snd_ack_head);
		BUFFER_DEBUG("%s: set snd_ack_head to %llu\n",__FUNCTION__, node->s_state.snd_ack_head);

	}
	spin_unlock_irqrestore(&node->s_state.lock, flags);
	hadm_queue_lock(queue, flags, 1);
	bio_wrapper = hadm_queue_head(queue, struct bio_wrapper, node);
	hadm_queue_unlock(queue, flags, 1);
	if(bio_wrapper == NULL) {
		return ;
	}

        spin_lock_irqsave(&buffer->lock, flags);
	if( buffer->io_completed_tail ) {
		entry = list_entry(buffer->io_completed_tail->list.next, struct bwr_data, list);
	} else {
		entry = list_entry(buffer->data_list.next, struct bwr_data, list);
	}
	BUFFER_DEBUG("%s:start search in buffer from %p(io_completed_tail = %p), bwr_seq = %llu to complete SYNC IO.\n",
			__FUNCTION__, entry, buffer->io_completed_tail, (unsigned long long)bwr_seq);
	prev_seq = 0;
	list_for_each_entry_from(entry, &buffer->data_list, list) {
		if(IS_ERR_OR_NULL(entry) || prev_seq == entry->meta.bwr_seq) {
			pr_warn("%s: hadm%d duplicate or error bwr_seq found in buffer, entry = %p, seq = %llu.\n",
					__FUNCTION__, node->hadmdev->minor, entry, prev_seq);
			hadmdev_set_error(node->hadmdev, __BWR_ERR);
			break;

		}
		prev_seq = entry->meta.bwr_seq;
		if(entry->meta.bwr_seq >= bwr_seq) {
			founded = 1;
			break;
		}
	}
        spin_unlock_irqrestore(&buffer->lock, flags);
	BUFFER_DEBUG("%s:search buffer for SYNC IO completed,  founded = %d, entry(%p private:%p seq:%llu)  bwr_seq = %llu,  bio_wrapper = %p\n",
			__FUNCTION__, founded, entry, entry->private,
			(unsigned long long) entry->meta.bwr_seq, (unsigned long long)bwr_seq,  bio_wrapper);
	if(founded && entry->meta.bwr_seq == bwr_seq && entry->private) {
	       //	&& entry->private == bio_wrapper) {
	       bio_wrapper = (struct bio_wrapper *)(entry->private);
	       BUFFER_DEBUG("%s:clear sync node mask of bio_wrapper %p(sync_node_mask:%llu) for node %d\n",
			       __FUNCTION__, bio_wrapper  , bio_wrapper->sync_node_mask, node->id);
	       sync_mask_clear_node(bio_wrapper, node->id, 1);
	}
}

void hadm_node_send_head_data_set(struct hadm_node *runnode, struct bwr_data *bwr_data)
{
	if (runnode->s_state.snd_head_data)
		bwr_data_put(runnode->s_state.snd_head_data);
	if (bwr_data) {
		bwr_data_get(bwr_data);
	}
	runnode->s_state.snd_head_data = bwr_data;
}

void hadm_node_send_head_data_update(struct hadm_node *runnode)
{
	struct bwr_data *head_data = runnode->s_state.snd_head_data;
	struct data_buffer *buffer = runnode->hadmdev->buffer;

	if (head_data) {
		head_data = get_buffer_next_data(buffer, head_data);
		bwr_data_put(runnode->s_state.snd_head_data);
		runnode->s_state.snd_head_data = head_data;
	}
}

void __hadm_node_send_head_inc(struct hadm_node *node, sector_t bwr_sector)
{
	struct bwr *bwr = node->hadmdev->bwr;
	sector_t snd_head_next = bwr_next_sector(bwr, node->s_state.snd_head);
	if(bwr_sector && node->s_state.snd_head  != bwr_sector) {
		pr_warn("%s:hadm%d node(%d)'s send_head(%llu:%llu) and pack bwr sector(%llu) mismatched\n",
				__FUNCTION__, node->hadmdev->minor,
				node->id,
				(unsigned long long)node->s_state.snd_head,
				(unsigned long long)snd_head_next,
				(unsigned long long) bwr_sector);

	}else {
		node->s_state.snd_head = snd_head_next;
	}
}

void hadm_node_send_head_inc(struct hadm_node *node, sector_t bwr_sector)
{
	unsigned long flags;

	spin_lock_irqsave(&node->s_state.lock, flags);
	__hadm_node_send_head_inc(node, bwr_sector);
	spin_unlock_irqrestore(&node->s_state.lock, flags);
}

void snd_head_condition_update(struct hadm_node *node, int field, int status)
{
	unsigned long flags;
	spin_lock_irqsave(&node->s_state.lock, flags);
	if (__hadm_node_get(&node->s_state, field) == status) {
		__hadm_node_send_head_inc(node, 0);
//		node->state.snd_head = list_entry(node->state.snd_head->list.next, struct bwr_data, list);
		if(status != C_SYNC) {
			node->s_state.snd_ack_head = node->s_state.snd_head;
		}
		spin_unlock_irqrestore(&node->s_state.lock, flags);
		hadm_node_send_head_data_update(node);
	} else
		spin_unlock_irqrestore(&node->s_state.lock, flags);
}

void __hadm_node_reset_send_head(struct hadm_node *node)
{
	node->s_state.snd_ack_head = node->s_state.snd_head = node->hadmdev->bwr->mem_meta.head[node->id];
//	if (node->s_state.snd_head_data)
//		bwr_data_put(node->s_state.snd_head_data);
//	node->s_state.snd_head_data = NULL;
}

void hadm_node_reset_send_head(struct hadm_node *node)
{
	unsigned long flags, flags1;
	uint64_t head ;
	spin_lock_irqsave(&node->s_state.lock, flags);
	read_lock_irqsave(&node->hadmdev->bwr->lock, flags1);
	head = node->hadmdev->bwr->mem_meta.head[node->id];
	if( node->s_state.snd_head != head) {
		pr_info("hadm%d reset node%d snd_head from %llu to %llu.\n",
				node->hadmdev->minor, node->id,  node->s_state.snd_head, head);
	}
	node->s_state.snd_ack_head = node->s_state.snd_head = head;
	read_unlock_irqrestore(&node->hadmdev->bwr->lock, flags1);
	spin_unlock_irqrestore(&node->s_state.lock, flags);
}

void disconnect_node(struct hadm_node *node)
{
	unsigned long flags, flags2;
	int nstate;
	int handshake;
	int primary_id;

	primary_id = hadmdev_get_primary_id(node->hadmdev);
	spin_lock_irqsave(&node->s_state.lock, flags);
	nstate = __hadm_node_get(&node->s_state, S_NSTATE);
	if (nstate != N_DISCONNECT) {
		pr_info("hadm%d:pre disconnect node %d(server %d), state changed...", 
				node->hadmdev->minor, node->kmod_id, node->id);
		if (get_node_id() == primary_id) {
			pr_info("hadm%d primary node: reset peer node node %d(server %d) info.\n",
				node->hadmdev->minor, node->kmod_id, node->id);
			/**
			 *如果已经在写节点的bitmap的时候，这时候节点如果将数据写入内存中的bitmap
			 *但是bitmap尚未flush到磁盘中，也就是head尚未更新为snd_head，disconnect_node
			 *会导致snd_head又reset到head，从而导致这段数据又重新读取一遍。
			 *在之前master版本不校验snd_head的seq是否递增，所以不会出问题。新版本的校验
			 *就会提示bug。
			 */
			if(__hadm_node_get(&node->s_state, S_CSTATE) == C_SYNC) {
				read_lock_irqsave(&node->hadmdev->bwr->lock, flags2);
				__hadm_node_reset_send_head(node);
				read_unlock_irqrestore(&node->hadmdev->bwr->lock, flags2);
			}
			__hadm_node_set(&node->s_state, S_NSTATE, N_DISCONNECT);
			__hadm_node_set(&node->s_state, S_HANDSHAKE, HS_FAIL);
			__hadm_node_set(&node->s_state, S_CSTATE, C_STOPPED);

			spin_unlock_irqrestore(&node->s_state.lock, flags);
//			sync_mask_clear_after_node_disconnect(node->hadmdev, node->id);
		} else {
			pr_info("hadm%d secondary node: reset peer node %d(server %d) info.\n",
				node->hadmdev->minor, node->kmod_id, node->id);
			if (primary_id == node->id) {
				pr_info("hadm%d peer node %d(server %d) is primary, clean primary info and p_data queue.\n",
						node->hadmdev->minor, node->kmod_id, node->id);
				__hadm_node_set(&node->s_state, S_ROLE, R_SECONDARY);
				hadmdev_set_primary(node->hadmdev, NULL);
				/**
				 *当primary节点断开时，需要停止写入尚未写入到bwr的P_DATA数据
				 *避免当hadm_main闪断时，老的数据和新的数据冲突
				 */
				hadm_pack_queue_clean(node->hadmdev->p_receiver_queue[P_DATA_TYPE]);

			}
			__hadm_node_set(&node->s_state, S_NSTATE, N_DISCONNECT);
			__hadm_node_set(&node->s_state, S_CSTATE, C_STOPPED);
			handshake = __hadm_node_get(&node->s_state, S_HANDSHAKE);
			if (handshake == HS_SUCCESS) {
				pr_info("hadm%d node %d(server %d) disconnect, reset handshake\n",
						node->hadmdev->minor, node->kmod_id, node->id);
				__hadm_node_set(&node->s_state, S_HANDSHAKE, HS_FAIL);
			}
			spin_unlock_irqrestore(&node->s_state.lock, flags);
		}
		node->kmod_id = -1;
		hadm_pack_queue_clean_for_host(node->hadmdev->p_sender_queue[P_DATA_TYPE], node);
		hadm_pack_queue_clean_for_host(node->hadmdev->p_receiver_queue[P_DATA_TYPE], node);
	} else {
		spin_unlock_irqrestore(&node->s_state.lock, flags);
	}
}

uint64_t gen_sync_node_mask(struct hadmdev *hadmdev)
{
	struct hadm_node *hadm_node;
	uint64_t sync_node_mask = 1;
	int local_node_id = get_node_id();
	unsigned long flags;
	/**FIXME lock update**/
	/**
	 *sync_node_mask的规则是：本地bwr占第1位，以后如果节点为SYNC节点，则相应的+1位置1
	 *如果存在一个SYNC节点，则local_node_id对应的位置1
	 *比如对于两个节点的同步模式，sync_node_mask= 0b0111
	 *对于两个节点的异步模式，sync_node_mask=0b01
	 */
	list_for_each_entry(hadm_node, &hadmdev->hadm_node_list, node) {
		if(hadm_node->id == local_node_id){
			continue;
		}
		spin_lock_irqsave(&hadm_node->s_state.lock, flags);
		if (hadm_node->conf.real_protocol == PROTO_SYNC)
		{
			sync_node_mask |= 1UL << (hadm_node->id+1);
		}
		spin_unlock_irqrestore(&hadm_node->s_state.lock, flags);
	}
	if(sync_node_mask != 1) {
	       	sync_node_mask |= 1UL << (local_node_id+1);
	}

	return sync_node_mask;
}


