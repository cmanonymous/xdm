#include "common.h"

hadm_log_cat *log_cat;

int log_init(const char *conf, const char *cat)
{
	int ret;
	hadm_log_cat *c;

	ret = zlog_init(conf);
	if(ret != 0) {
		fprintf(stderr, "log init failed!\n");
		return -1;
	}

	c = zlog_get_category(cat);
	if(c == NULL) {
		fprintf(stderr, "get log category failed!\n");
		zlog_fini();
		return -1;
	}

	log_cat = c;

	return 0;
}

void log_fini()
{
	zlog_fini();
}
