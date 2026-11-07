#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

char *read_file(const char *path, size_t max_bytes, char **err) {
    if (err) *err = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) {
            char b[256];
            snprintf(b, sizeof b, "open %s: %s", path, strerror(errno));
            *err = xstrdup(b);
        }
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 || (size_t)st.st_size > max_bytes) {
        if (err) *err = xstrdup("file is too large or unreadable");
        close(fd);
        return NULL;
    }
    size_t cap = (size_t)st.st_size + 1;
    char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        if (err) *err = xstrdup("out of memory");
        return NULL;
    }
    size_t used = 0;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + used, (size_t)st.st_size - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (err) *err = xstrdup("read failed");
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    buf[used] = '\0';
    close(fd);
    return buf;
}

char *trim_whitespace(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    return s;
}

void iso_time(time_t t, char *buf, size_t len) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void iso_now(char *buf, size_t len) {
    iso_time(time(NULL), buf, len);
}

int parse_int_range(const char *s, int fallback, int min, int max) {
    if (!s || !*s) return fallback;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !end || *end != '\0' || v < min || v > max) return fallback;
    return (int)v;
}

int constant_time_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strlen(a);
    size_t lb = strlen(b);
    size_t n = la < lb ? la : lb;
    unsigned char diff = (unsigned char)(la ^ lb);
    if (n) diff |= CRYPTO_memcmp(a, b, n);
    return diff == 0;
}

int is_loopback(const char *bind) {
    if (!bind) return 0;
    return strcmp(bind, "127.0.0.1") == 0 || strcmp(bind, "::1") == 0 ||
           strcmp(bind, "localhost") == 0;
}

void wipe_free(char *s) {
    if (!s) return;
    OPENSSL_cleanse(s, strlen(s));
    free(s);
}
