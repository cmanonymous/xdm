#ifndef __LOG_H__
#define __LOG_H__

#include <zlog.h>

typedef zlog_category_t hadm_log_cat;

extern hadm_log_cat *log_cat;

int log_init(const char *conf, const char *cat);

void log_fini();

#define log_fatal(format, args...) zlog_fatal(log_cat, format, ##args)

#define log_error(format, args...) zlog_error(log_cat, format, ##args)

#define log_warn(format, args...) zlog_warn(log_cat, format, ##args)

#define log_notice(format, args...) zlog_notice(log_cat, format, ##args)

#define log_info(format, args...) zlog_info(log_cat, format, ##args)

#define log_debug(format, args...) zlog_debug(log_cat, format, ##args)

#endif // __LOG_H__
