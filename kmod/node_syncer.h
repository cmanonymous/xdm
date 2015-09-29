#ifndef NODE_SYNCER_H
#define NODE_SYNCER_H

extern int sync_local_thread(void *arg);
extern int sync_remote_thread(void *arg);
extern int sync_dbm_thread(void *arg);

#endif	/* NODE_SYNCER_H */
