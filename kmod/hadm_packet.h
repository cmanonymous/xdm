#ifndef HADM_PACKET_H
#define HADM_PACKET_H

#include "hadm_def.h"

/*
 * struct packet{} already define in include/packet.inc,
 * hadm_def.h already included it.
 */

struct hadmdev;
struct hadm_node;

extern void dump_packet(const char *msg, struct packet *pack);
extern struct packet *packet_alloc(size_t len, int gfp_mask);
extern struct packet *packet_alloc_for_node(size_t len, int gfp_mask,
		struct hadm_node *node);
extern void packet_free(struct packet *pack);
extern void packet_init(struct packet *pack, uint8_t type, uint8_t dev_id,
			uint32_t node_to, uint64_t dev_sector, uint64_t bwr_sector, uint64_t bwr_seq,
			uint32_t nr_node_state, int16_t errcode);
extern struct packet *packet_alloc_node_state_packet(struct hadmdev *hadmdev);

extern int packet_send(struct packet *snd_pack);
struct hadm_pack_node;
extern int packet_node_send(struct hadm_pack_node *node, int block);
extern int send_uptodate_packet(struct hadm_node *hadm_node, uint64_t bwr_seq);
struct bwr_data;
extern int sync_node_bwrdata(struct hadm_node *node, struct bwr_data *data,
		int sync_type);
extern int rssync_node_sector(struct hadm_node *hadm_node, sector_t dev_sector);

#endif	/* HADM_PACKET_H */
