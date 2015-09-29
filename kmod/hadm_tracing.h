#ifndef __HADM_TRACING_H__
#define __HADM_TRACING_H__

#include <linux/tracepoint.h>

#include "hadm_def.h"
#include "hadm_device.h"

DECLARE_TRACE(make_request,
		TP_PROTO(struct hadmdev *hadmdev),
		TP_ARGS(hadmdev));

DEFINE_TRACE(make_request);


#endif // __HADM_TRACING_H__
