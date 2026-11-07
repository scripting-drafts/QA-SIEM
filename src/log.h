#ifndef QA_SIEM_LOG_H
#define QA_SIEM_LOG_H

#include <stdarg.h>

void log_msg(const char *level, const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);

#endif
