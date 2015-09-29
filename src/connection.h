#ifndef __CONNECTION_H__
#define __CONNECTION_H__

int check_all_connected(struct node_list *node_list);

void clean_connection(struct node_list *node_list);

int node_list_connect(struct node_list *node_list);

int connect_function(void *data);

void connect_timer_cb(evutil_socket_t fd, short event, void *args);

#endif // __CONNECTION_H__
