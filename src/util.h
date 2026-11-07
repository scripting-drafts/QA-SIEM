#ifndef QA_SIEM_UTIL_H
#define QA_SIEM_UTIL_H

#include <stddef.h>
#include <time.h>

char *xstrdup(const char *s);
char *read_file(const char *path, size_t max_bytes, char **err);
char *trim_whitespace(char *s);
void iso_time(time_t t, char *buf, size_t len);
void iso_now(char *buf, size_t len);
int parse_int_range(const char *s, int fallback, int min, int max);
int constant_time_eq(const char *a, const char *b);
int is_loopback(const char *bind);
void wipe_free(char *s);

#endif
