#ifndef QA_SIEM_SERVER_H
#define QA_SIEM_SERVER_H

#include "db.h"

#include <stddef.h>
#include <time.h>

#define QA_SIEM_VERSION "1.0.0"

struct MHD_Daemon;

typedef struct {
    siem_db *db;
    const siem_rules *rules;
    char *token;
    char *web_root;
    int retention_days;
    int allow_no_auth;
    time_t started;
    char *tls_key_mem;
    char *tls_cert_mem;
} siem_server;

struct MHD_Daemon *server_start(siem_server *srv, const char *bind, int port,
                                const char *tls_cert, const char *tls_key,
                                char **err);
void server_stop(struct MHD_Daemon *daemon);

#endif
