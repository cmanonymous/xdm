#include <linux/seq_file.h>

#include "../include/common.inc"
#include "../config.h"
#include "../include/packet.inc"

#include "hadm_node.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "utils.h"
#include "bwr.h"
#include "buffer.h"

#include "hadm_proc_show.h"

#define HADM_PROC       "hadm"
#define BWR_ANCHOR_PROC "bwr_anchor"
#define BIO_QUEUE	"queue"
#define BWR_INFO	"bwr"

struct hadm_show_func proc_show_funs[] = {
	{HADM_PROC, hadm_proc_show},
	{BIO_QUEUE, bio_queue_show}, 
	{BWR_INFO, bwr_info_show}, 
	{NULL, NULL},
};
#define NODE_STATE_FMT_LEN 20
#define NODE_STATIC_STATE_FMT "%-*s:\t%d\n" /*device id*/ \
	"%-*s:\t%d\n" /*Local node id*/ \
	"%-*s:\t%d\n" /*Primary node id*/ \
	"%-*s:\t%s\n" /*node role*/ \
	"%-*s:\t%llu\n" /*bdev size*/ \
	"%-*s:\t%llu\n" /*bwr size*/ \
	"%-*s:\t%lu\n" /*bwr sectors*/ \
	"%-*s:\t%lu\n" /*bwr start sector*/ \
	"%-*s:\t%lu\n" /*device io sector*/ \


#include "../include/common_string.h"

#define MAX_STATE_STR_LEN 800
void get_head_state_str(char *state_str, uint64_t *head)
{
	int i, l;
	state_str[0] = 0 ;
	for(i = 0; i < MAX_NODES; i++) {
		l = strlen(state_str);
		snprintf(state_str + l, MAX_STATE_STR_LEN - 1, "%lld ", (long long)head[i]);
	}
}

int hadm_proc_show(struct seq_file *seq, void *v)
{
	struct hadmdev *dev;
	struct hadm_node *runnode;
	int primary_id, local_node_id = get_node_id();
	char *state_str = NULL;
	uint64_t *head = NULL;
	unsigned long flags;
	int i;
	seq_printf(seq, "%s version %s git commit %s\n", "hadm", VERSION, GIT_COMMIT);
	state_str = kzalloc(sizeof(char) * MAX_STATE_STR_LEN, GFP_KERNEL);
	head = kzalloc(sizeof(uint64_t) * MAX_NODES, GFP_KERNEL);
	if(IS_ERR_OR_NULL(head) || IS_ERR_OR_NULL(state_str)){
		goto hadm_proc_show_out;
	}
	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		primary_id = hadmdev_get_primary_id(dev);
		seq_printf(seq, NODE_STATIC_STATE_FMT, 
				NODE_STATE_FMT_LEN, "Id", dev->minor, 
				NODE_STATE_FMT_LEN, "Local Id", local_node_id, 
				NODE_STATE_FMT_LEN, "Primary Id", primary_id, 
				NODE_STATE_FMT_LEN, "Role", local_node_id == primary_id ? "Primary" : "Secondary",
				NODE_STATE_FMT_LEN, "BDEV Size", (unsigned long long)dev->bdev_disk_size << 9,
				NODE_STATE_FMT_LEN, "BWR Size", (unsigned long long)dev->bwr->max_size << 9,
				NODE_STATE_FMT_LEN, "BWR Sectors", dev->bwr->max_sector,
				NODE_STATE_FMT_LEN, "BWR Start Sector", dev->bwr->start_sector,
				NODE_STATE_FMT_LEN, "Device State", dev->state);

		read_lock_irqsave(&dev->bwr->lock, flags);

		snprintf(state_str, MAX_STATE_STR_LEN - 1, "%d %llu %llu", 
				dev->bwr->mem_meta.local_primary.id,
				dev->bwr->mem_meta.local_primary.uuid,
				dev->bwr->mem_meta.local_primary.bwr_seq);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Local Primary Info", state_str);

		snprintf(state_str, MAX_STATE_STR_LEN - 1, "%d %llu %llu", 
				dev->bwr->mem_meta.last_primary.id,
				dev->bwr->mem_meta.last_primary.uuid,
				dev->bwr->mem_meta.last_primary.bwr_seq);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Last Primary Info", state_str);
		seq_printf(seq, "%-*s:\t%s\n", 
				NODE_STATE_FMT_LEN, "Data State", dstate_name[dev->bwr->mem_meta.disk_state]);

		seq_printf(seq, "%-*s:\t%llu\n", 
				 NODE_STATE_FMT_LEN, "BWR Tail", dev->bwr->mem_meta.tail);
		memcpy((void *)head, (void *)dev->bwr->mem_meta.head, sizeof(uint64_t) * MAX_NODES);
		read_unlock_irqrestore(&dev->bwr->lock, flags);
		//show node head
		
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node Head", state_str);

		//show node snd_head
		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id != local_node_id) {
				head[runnode->id] = runnode->s_state.snd_head;
			}
		}
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node Snd Head", state_str);
		//show snd_ack_head
		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id != local_node_id) {
				head[runnode->id] = runnode->s_state.snd_ack_head;
			}
		}
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node Snd Ack Head", state_str);
		//show dbm
		for(i = 0 ; i < MAX_NODES; i++) head[i] = 0;
		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id == local_node_id) {
				head[runnode->id] = 0;
			}else{
				head[runnode->id] = atomic_read(&runnode->dbm->nr_bit);
			}
		}
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node DBM Bits", state_str);

		for(i = 0 ; i < MAX_NODES; i++) head[i] = -1;
		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id == local_node_id) {
				head[runnode->id] = 1;
			}else{
				head[runnode->id] = runnode->s_state.n_state;
			}
		}
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node Connected", state_str);

		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id == local_node_id) {
				head[runnode->id] = 1;
			}else{
				head[runnode->id] = runnode->s_state.data_state;
			}
		}
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node Data State", state_str);

		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id == local_node_id) {
				head[runnode->id] = C_SYNC;
			}else{
				head[runnode->id] = runnode->s_state.c_state;
			}
		}
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node Rep State", state_str);

		head[local_node_id] = PROTO_ASYNC;
		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id != local_node_id) {
				head[runnode->id] = runnode->conf.real_protocol;
				if(head[runnode->id] == PROTO_SYNC)
					head[local_node_id] = PROTO_SYNC;
			}
		}
		get_head_state_str(state_str, head);
		seq_printf(seq, "%-*s:\t%s\n", NODE_STATE_FMT_LEN, "Node Rep Mode", state_str);



	       	seq_printf(seq, "\n");
	}
hadm_proc_show_out:
	if(head)
		kfree(head);
	if(state_str)
		kfree(state_str);

	return 0;
}

int bwr_anchor_show(struct seq_file *seq, void *v)
{
	struct hadmdev *dev;
	struct hadm_node *runnode;
	int local_node_id, primary_id;
	seq_printf(seq, "%s version %s\ngit commit %s\n", "hadm", VERSION, GIT_COMMIT);
	local_node_id=get_node_id();
	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		primary_id=hadmdev_get_primary_id(dev);
		if(local_node_id!=primary_id) {
			continue;
		}
		seq_printf(seq, "resource: %s,local id:%d,primary id:%d\n", dev->name,local_node_id,primary_id);
		seq_printf(seq,"bwr tail:%llu,uuid:%llu,seq id:%llu\n",
				(unsigned long long)(dev->bwr->mem_meta.tail),
				(unsigned long long)(dev->bwr->mem_meta.local_primary.uuid),
				(unsigned long long)(dev->bwr->mem_meta.local_primary.bwr_seq));
		seq_printf(seq,"id\t\thead\tsnd head\tsnd ack head\n");
		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id==local_node_id) {
				seq_printf(seq,"%d(local)\t%llu\n",
						local_node_id,(unsigned long long)dev->bwr->mem_meta.head[local_node_id]);
			}else {
				seq_printf(seq,"%d\t\t%llu\t%llu\t\t%llu\n",
						runnode->id,
						(unsigned long long)dev->bwr->mem_meta.head[runnode->id],
						(unsigned long long)runnode->s_state.snd_head,
						(unsigned long long)runnode->s_state.snd_ack_head
						);

			}
		}
		seq_printf(seq,"\n");
	}

	return 0;
}

int bio_queue_show(struct seq_file *seq, void *v) 
{
	struct hadmdev *dev;
	struct data_buffer *buffer;
	struct bwr_data *tail_data;
	int local_node_id, primary_id;
	local_node_id = get_node_id();
	seq_printf(seq, "%s version %s\ngit commit %s\n", "hadm", VERSION, GIT_COMMIT);
	seq_printf(seq, "cmd queue(sender receiver): (%u/%u %u/%u)--\n", 
			g_hadm->cmd_sender_queue->len, 
			g_hadm->cmd_sender_queue->maxlen, 
			g_hadm->cmd_receiver_queue->len, 
			g_hadm->cmd_receiver_queue->maxlen);
	seq_printf(seq, "all sender queue(meta/data): %u/%u\n", 
			atomic_read(&g_hadm->sender_queue_size[P_CTRL_TYPE]),
			atomic_read(&g_hadm->sender_queue_size[P_DATA_TYPE]));
	read_lock(&g_hadm->dev_list_lock);
	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		primary_id = hadmdev_get_primary_id(dev);
		seq_printf(seq, "resource: %s,local id:%d,primary id:%d\n", dev->name,local_node_id,primary_id);
		seq_printf(seq, "packet receiver queue: meta(%u/%u), data(%u/%u)\n", 
			dev->p_receiver_queue[P_CTRL_TYPE]->len, 
			dev->p_receiver_queue[P_CTRL_TYPE]->maxlen, 
			dev->p_receiver_queue[P_DATA_TYPE]->len, 
			dev->p_receiver_queue[P_DATA_TYPE]->maxlen
			);
		seq_printf(seq, "packet sender queue: meta(%u/%u/%u), data(%u/%u/%u)\n", 
			dev->p_sender_queue[P_CTRL_TYPE]->len, 
			dev->p_sender_queue[P_CTRL_TYPE]->maxlen,
			dev->p_sender_queue[P_CTRL_TYPE]->reserved,
			dev->p_sender_queue[P_DATA_TYPE]->len,
			dev->p_sender_queue[P_DATA_TYPE]->maxlen,
			dev->p_sender_queue[P_DATA_TYPE]->reserved
			);

		seq_printf(seq, "bio_rd_queue: (%u/%u)\n", 
				dev->bio_wrapper_queue[HADM_IO_READ]->len, 
				dev->bio_wrapper_queue[HADM_IO_READ]->maxlen); 
		seq_printf(seq, "bio_wr_queue: length %u, unused %u, max %u, io_pending %u\n", 
				dev->bio_wrapper_queue[HADM_IO_WRITE]->len, 
				dev->bio_wrapper_queue[HADM_IO_WRITE]->unused, 
				dev->bio_wrapper_queue[HADM_IO_WRITE]->maxlen,
				atomic_read(&dev->bwr_io_pending));
		buffer = dev->buffer;
		tail_data  = list_entry(buffer->data_list.prev,  struct bwr_data,  list);
		seq_printf(seq, "data buffer: data size %lld, inuse_size %lld \ninuse_head->io_completed_tail->tail(%p:%llu->%p:%llu->%p:%llu).\n",
			buffer->data_size, buffer->inuse_size,
			buffer->inuse_head, buffer->inuse_head ? bwr_data_seq(buffer->inuse_head) : 0,
			buffer->io_completed_tail, buffer->io_completed_tail ? bwr_data_seq(buffer->io_completed_tail):0, 
			tail_data, buffer->inuse_head ? bwr_data_seq(tail_data) : 0);

		seq_printf(seq,"\n");

	}
	read_unlock(&g_hadm->dev_list_lock);
	return 0;


}

void bwr_meta_show(struct seq_file *seq, struct bwr_meta *meta)
{
	int i;

	seq_printf(seq, "head:\n");
	for (i = 0; i < MAX_NODES; i++){
		if(meta->head[i] != INVALID_SECTOR) {
			seq_printf(seq, "%d:%llu ", i, (unsigned long long)meta->head[i]);
		}
	}
	seq_printf(seq, "\ntail: %llu, disk_state: %d\n\n", (unsigned long long)meta->tail, meta->disk_state);

	seq_printf(seq, "last_primary: id=%d, uuid=%llu, bwr_seq=%llu\n",
			meta->last_primary.id, (unsigned long long)meta->last_primary.uuid,
			(unsigned long long)meta->last_primary.bwr_seq);
	seq_printf(seq, "local_primary: id=%d, uuid=%llu, bwr_seq=%llu\n",
			meta->local_primary.id, (unsigned long long)meta->local_primary.uuid,
			(unsigned long long)meta->local_primary.bwr_seq);
}

int bwr_info_show(struct seq_file *seq, void *v) 
{
	struct hadmdev *dev;
	unsigned long flags;
	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		read_lock_irqsave(&dev->bwr->lock, flags);
		seq_printf(seq, "============dump bwr info for dev hadm%d===============\n", dev->minor);
		seq_printf(seq, "bwr inuse_size = %lu, min_disk_head = %lu, min_node_mask = %u, last_seq = %lu\n", 
				dev->bwr->inuse_size, dev->bwr->min_disk_head, dev->bwr->min_node_mask, dev->bwr->last_seq);
		seq_printf(seq, "=============bwr mem_data===============\n"); 
		bwr_meta_show(seq, &dev->bwr->mem_meta);
		seq_printf(seq, "=============bwr disk_data===============\n"); 
		bwr_meta_show(seq, &dev->bwr->disk_meta);
		read_unlock_irqrestore(&dev->bwr->lock, flags);


	}
	return 0;


}
