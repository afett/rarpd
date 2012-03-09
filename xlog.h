#ifndef XLOG_H
#define XLOG_H

#include <syslog.h>

#define XLOG_DEBUG(...) \
	syslog(LOG_DEBUG, __VA_ARGS__)
#define XLOG_INFO(...) \
	syslog(LOG_INFO, __VA_ARGS__)
#define XLOG_ERR(...) \
	syslog(LOG_ERR, __VA_ARGS__)
#define XLOG_WARNING(...) \
	syslog(LOG_WARNING, __VA_ARGS__)

#endif
