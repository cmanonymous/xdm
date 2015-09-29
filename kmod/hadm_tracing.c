#include <linux/module.h>
#include "hadm_tracing.h"

enum {
	TRACE_MAKE_REQUEST  = 0x0001,
};

enum {
	TRACE_LEVEL_1,
	TRACE_LEVEL_2,
	TRACE_LEVEL_DEFAULT,
};

unsigned int trace_mask = 0;
unsigned int trace_level = TRACE_LEVEL_DEFAULT;

module_param(trace_mask, uint, 0644);
module_param(trace_level, uint, 0644);

static void probe_make_request(void *data, struct hadmdev *hadmdev)
{
	pr_info("trace make_request");
}

static int hadm_trace_init(void)
{
	int ret = 0;

	if(trace_mask & TRACE_MAKE_REQUEST) {
		ret = register_trace_make_request(probe_make_request, NULL);
	}

	return ret;
}

static void hadm_trace_exit(void)
{
	if(trace_mask & TRACE_MAKE_REQUEST) {
		unregister_trace_make_request(probe_make_request, NULL);
	}
}

module_init(hadm_trace_init);
module_exit(hadm_trace_exit);
MODULE_LICENSE("GPL");
