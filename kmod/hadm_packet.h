#ifndef HADM_PACKET_H
#define HADM_PACKET_H

#include "hadm_def.h"
#include <linux/net.h>

/*
 * struct packet{} already define in include/packet.inc,
 * hadm_def.h already included it.
 */


enum hdpack_data_type {
	HADM_DATA_NORMAL,
	HADM_DATA_PAGE,
};

struct hdpack_data {
	enum hdpack_data_type type;
	//unsigned long flags;
	atomic_t count;		/* refcnt */
	uint32_t len;		/* data len */

	uint32_t vcnt;		/* vcnt for hv, used only for HADM_DATA_PAGE */
	uint32_t max_vcnt;	/* max hv cnt, used only for HADM_DATA_PAGE */
	union {
		struct hadm_io *hv;	/* hv to actual data */
		char *buff;
	};
};

extern void dump_hdpack_data(const char *str, struct hdpack_data *data);
extern struct hdpack_data *hdpack_data_alloc(gfp_t flags, uint32_t maxsize,
		int type);
extern void hdpack_data_free(struct hdpack_data *data);
extern void hdpack_data_get(struct hdpack_data *data);
extern int hdpack_data_add_page(struct hdpack_data *data, struct page *page,
		int start, int len);

struct hdpacket {
	struct list_head list;

	/* head.len vs data->len:
	 *	head.len: length of data to send
	 *	data->len: length of data
	 */
	struct packet head;
#define hp_magic	head.magic
#define hp_len		head.len
#define hp_type		head.type
	struct hdpack_data *data;

	void *private;	/* used by user. for cmd packet, point to cmd socket */
};

extern struct hdpacket *hdpacket_alloc(gfp_t flags, uint32_t data_len,
		int data_type);
extern struct hdpacket *site_hdpacket_alloc(gfp_t flags, uint32_t len, int type);
extern struct hdpacket *node_hdpacket_alloc(gfp_t flags, uint32_t len, int type);
extern void hdpacket_clear_data(struct hdpacket *pack);
extern void hdpacket_free(struct hdpacket *pack);

extern int hdpacket_add_page(struct hdpacket *pack, struct page *page,
		int start, int len);
extern struct hdpacket *hdpacket_clone(struct hdpacket *pack);

extern int hdpacket_send(struct socket *sock, struct hdpacket *pack);
extern struct hdpacket *hdpacket_recv(struct socket *sock);

struct hadmdev;
extern void dump_packet(const char *msg, struct packet *pack);
extern struct packet *packet_alloc(size_t len, int gfp_mask);
extern void packet_free(struct packet *pack);
extern void packet_init(struct packet *pack, uint8_t type, uint8_t dev_id,
			uint32_t node_to, uint64_t dev_sector, uint64_t bwr_sector,
			uint32_t nr_site_state, int16_t errcode);

extern int packet_send(struct packet *snd_pack);
struct hadm_site;
extern int send_uptodate_packet(struct hadm_site *hadm_site, uint64_t bwr_seq);
struct bwr_data;
extern int sync_site_bwrdata(struct hadm_site *site, struct bwr_data *data,
		int sync_type);
extern int rssync_site_sector(struct hadm_site *hadm_site, sector_t dev_sector);

extern int send_master_notify(int node_to);
#endif	/* HADM_PACKET_H */
