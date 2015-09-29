#ifndef __PACKET_H__
#define __PACKET_H__

#define SOCK_PACKET_HDR_LEN 8

struct sock_packet {
	union {
		struct {
			uint8_t node_id;
			uint8_t type;
		}__attribute__((packed));

		char __pack[SOCK_PACKET_HDR_LEN];
	};
};

struct z_packet {
	union {
		struct {
			uint32_t len;
			uint32_t data_len;
		}__attribute__((packed));
	};

	char data[0];
};

struct sock_packet *alloc_sock_packet();

struct sock_packet *create_sock_packet(int node_id, int type);

void free_sock_packet(struct sock_packet *pkt);

int sock_packet_send(int fd, struct sock_packet *pkt);

int sock_packet_recv(int fd, struct sock_packet *pkt);

struct packet *alloc_packet(uint32_t len);

struct packet *alloc_packet0();

void free_packet(struct packet *pkt);

int packet_send(int fd, struct packet *pkt);

struct packet *packet_recv_header(int fd);

struct packet *packet_recv(int fd);

int packet_set_node_to(int nr, struct packet *packet);;

int packet_test_node_to(int nr, struct packet *packet);

struct packet *create_config_packet(struct config *cfg);

struct packet *packet_clone(struct packet *orig_pkt);

struct z_packet *alloc_z_packet(uint32_t len);

struct z_packet *alloc_z_packet0();

void free_z_packet(struct z_packet *z_pkt);

struct z_packet *pack_z_packet(struct packet *pkt);

struct packet *unpack_z_packet(struct z_packet *z_pkt);

struct z_packet *z_packet_recv_header(int fd);

struct z_packet *z_packet_recv(int fd);

int z_packet_send(int fd, struct z_packet *pkt);

void packet_log_debug(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str);

void packet_log_info(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str);

void packet_log_warn(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str);

void packet_log_error(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str);

void bit_index_to_str(int bit, char *str, int len);

void log_packet_header(struct packet *pkt,
		       void (*pkt_log_fn)(struct packet *, const char *, const char *));



#endif // __PACKET_H__
