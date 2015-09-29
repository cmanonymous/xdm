#ifndef __HADM_PROC_SHOW_H__
#define __HADM_PROC_SHOW_H__

struct seq_file;

struct hadm_show_func {
	const char *file_name;
	int (*show)(struct seq_file *, void *);
};

extern int hadm_proc_show(struct seq_file *seq, void *v);
extern int bwr_anchor_show(struct seq_file *seq, void *v);
extern int site_status_show(struct seq_file *seq, void *v);
extern int node_status_show(struct seq_file *seq, void *v);

#endif /* __HADM_PROC_SHOW_H__ */
