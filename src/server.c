#include "server.h"

#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <microhttpd.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_BODY (8U * 1024U * 1024U)
#define MAX_BATCH 5000
#define MAX_ERRORS 10

#ifndef MHD_HTTP_CONTENT_TOO_LARGE
#define MHD_HTTP_CONTENT_TOO_LARGE 413
#endif

typedef struct {
    char *body;
    size_t len;
    int too_large;
    int done;
} request_ctx;

static void request_completed(void *cls, struct MHD_Connection *connection,
                              void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)connection;
    (void)toe;
    request_ctx *ctx = *con_cls;
    if (!ctx) return;
    free(ctx->body);
    free(ctx);
    *con_cls = NULL;
}

static int authorized(siem_server *srv, struct MHD_Connection *conn) {
    if (srv->allow_no_auth && (!srv->token || !*srv->token)) return 1;
    const char *h = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    if (!h || strncmp(h, "Bearer ", 7) != 0) return 0;
    return constant_time_eq(h + 7, srv->token);
}

static enum MHD_Result send_json(struct MHD_Connection *conn, unsigned int status,
                                 cJSON *obj) {
    char *text = cJSON_PrintUnformatted(obj);
    if (!text) return MHD_NO;
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(text), text, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(text);
        return MHD_NO;
    }
    MHD_add_response_header(resp, "Content-Type", "application/json; charset=utf-8");
    MHD_add_response_header(resp, "Cache-Control", "no-store");
    MHD_add_response_header(resp, "X-Content-Type-Options", "nosniff");
    enum MHD_Result rc = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return rc;
}

static enum MHD_Result send_error(struct MHD_Connection *conn, unsigned int status,
                                  const char *message) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "error", message ? message : "request failed");
    enum MHD_Result rc = send_json(conn, status, obj);
    cJSON_Delete(obj);
    return rc;
}

static enum MHD_Result send_unauthorized(struct MHD_Connection *conn) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen("{\"error\":\"unauthorized\"}"), "{\"error\":\"unauthorized\"}",
        MHD_RESPMEM_PERSISTENT);
    if (!resp) return MHD_NO;
    MHD_add_response_header(resp, "Content-Type", "application/json; charset=utf-8");
    MHD_add_response_header(resp, "WWW-Authenticate", "Bearer realm=\"qa-siem\"");
    enum MHD_Result rc = MHD_queue_response(conn, MHD_HTTP_UNAUTHORIZED, resp);
    MHD_destroy_response(resp);
    return rc;
}

static enum MHD_Result serve_static(siem_server *srv, struct MHD_Connection *conn,
                                    const char *name, const char *mime) {
    size_t n = strlen(srv->web_root) + strlen(name) + 2;
    char *path = malloc(n);
    if (!path) return MHD_NO;
    snprintf(path, n, "%s/%s", srv->web_root, name);
    char *err = NULL;
    char *data = read_file(path, 2 * 1024 * 1024, &err);
    free(path);
    if (!data) {
        free(err);
        return send_error(conn, MHD_HTTP_NOT_FOUND, "not found");
    }
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(data), data, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(data);
        return MHD_NO;
    }
    MHD_add_response_header(resp, "Content-Type", mime);
    MHD_add_response_header(resp, "X-Content-Type-Options", "nosniff");
    MHD_add_response_header(resp, "Content-Security-Policy",
                            "default-src 'self'; script-src 'self'; style-src 'self'; "
                            "connect-src 'self'; img-src 'self' data:; "
                            "base-uri 'none'; frame-ancestors 'none'");
    enum MHD_Result rc = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return rc;
}

static const char *query_arg(struct MHD_Connection *conn, const char *key) {
    return MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, key);
}

static enum MHD_Result handle_stats(siem_server *srv, struct MHD_Connection *conn) {
    cJSON *stats = NULL;
    char *err = NULL;
    if (db_stats(srv->db, &stats, &err) != 0) {
        enum MHD_Result rc = send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                        err ? err : "stats failed");
        free(err);
        return rc;
    }
    cJSON_AddNumberToObject(stats, "uptime_s", (double)(time(NULL) - srv->started));
    cJSON_AddStringToObject(stats, "version", QA_SIEM_VERSION);
    enum MHD_Result rc = send_json(conn, MHD_HTTP_OK, stats);
    cJSON_Delete(stats);
    return rc;
}

static enum MHD_Result handle_events(siem_server *srv, struct MHD_Connection *conn) {
    int limit = parse_int_range(query_arg(conn, "limit"), 100, 1, 1000);
    const char *since = query_arg(conn, "since");
    const char *severity = query_arg(conn, "severity");
    const char *host = query_arg(conn, "host_id");
    cJSON *arr = NULL;
    char *err = NULL;
    if (db_events(srv->db, since, severity, host, limit, &arr, &err) != 0) {
        enum MHD_Result rc = send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                        err ? err : "events failed");
        free(err);
        return rc;
    }
    enum MHD_Result rc = send_json(conn, MHD_HTTP_OK, arr);
    cJSON_Delete(arr);
    return rc;
}

static enum MHD_Result handle_alerts(siem_server *srv, struct MHD_Connection *conn) {
    int limit = parse_int_range(query_arg(conn, "limit"), 100, 1, 1000);
    const char *status = query_arg(conn, "status");
    cJSON *arr = NULL;
    char *err = NULL;
    if (db_alerts(srv->db, status, limit, &arr, &err) != 0) {
        enum MHD_Result rc = send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                        err ? err : "alerts failed");
        free(err);
        return rc;
    }
    enum MHD_Result rc = send_json(conn, MHD_HTTP_OK, arr);
    cJSON_Delete(arr);
    return rc;
}

static enum MHD_Result handle_ack(siem_server *srv, struct MHD_Connection *conn,
                                  const char *body) {
    cJSON *req = cJSON_Parse(body);
    if (!req) return send_error(conn, MHD_HTTP_BAD_REQUEST, "invalid JSON");
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(req, "id");
    if (!cJSON_IsNumber(id) || id->valuedouble < 1 ||
        id->valuedouble > (double)LONG_MAX) {
        cJSON_Delete(req);
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "id must be a positive number");
    }
    char *err = NULL;
    int rc = db_ack(srv->db, (long)id->valuedouble, &err);
    cJSON_Delete(req);
    if (rc == 1) {
        enum MHD_Result out = send_error(conn, MHD_HTTP_NOT_FOUND,
                                         err ? err : "alert not found");
        free(err);
        return out;
    }
    if (rc != 0) {
        enum MHD_Result out = send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                         err ? err : "ack failed");
        free(err);
        return out;
    }
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "acked");
    enum MHD_Result out = send_json(conn, MHD_HTTP_OK, resp);
    cJSON_Delete(resp);
    return out;
}

typedef struct {
    int accepted;
    int duplicates;
    int alerts;
    int rejected;
    char *errors[MAX_ERRORS];
    int error_count;
} ingest_result;

static void ingest_error(ingest_result *res, const char *message) {
    if (res->error_count < MAX_ERRORS) {
        res->errors[res->error_count++] = xstrdup(message ? message : "invalid event");
    }
}

static int ingest_one(siem_server *srv, cJSON *item, ingest_result *res) {
    char *err = NULL;
    int inserted = 0;
    int alerted = 0;
    if (db_ingest(srv->db, srv->rules, item, &err, &inserted, &alerted) != 0) {
        ingest_error(res, err ? err : "ingest failed");
        free(err);
        res->rejected++;
        return 0;
    }
    if (inserted) {
        res->accepted++;
        res->alerts += alerted;
    } else {
        res->duplicates++;
    }
    return 1;
}

static int ingest_document(siem_server *srv, const char *body, ingest_result *res) {
    cJSON *root = cJSON_Parse(body);
    if (root) {
        if (cJSON_IsArray(root)) {
            int n = cJSON_GetArraySize(root);
            if (n > MAX_BATCH) {
                ingest_error(res, "batch exceeds limit");
                cJSON_Delete(root);
                return -1;
            }
            const cJSON *item = NULL;
            cJSON_ArrayForEach(item, root) {
                if (!cJSON_IsObject(item)) {
                    res->rejected++;
                    ingest_error(res, "batch item is not an object");
                    continue;
                }
                ingest_one(srv, (cJSON *)item, res);
            }
        } else if (cJSON_IsObject(root)) {
            ingest_one(srv, root, res);
        } else {
            ingest_error(res, "body must be an object or array");
            res->rejected++;
        }
        cJSON_Delete(root);
        return 0;
    }

    char *copy = xstrdup(body);
    if (!copy) return -1;
    char *save = NULL;
    char *line = strtok_r(copy, "\n", &save);
    int lines = 0;
    while (line) {
        char *clean = trim_whitespace(line);
        if (*clean) {
            lines++;
            if (lines > MAX_BATCH) {
                ingest_error(res, "NDJSON batch exceeds limit");
                break;
            }
            cJSON *item = cJSON_Parse(clean);
            if (!item) {
                res->rejected++;
                ingest_error(res, "invalid NDJSON line");
            } else {
                if (cJSON_IsObject(item)) {
                    ingest_one(srv, item, res);
                } else {
                    res->rejected++;
                    ingest_error(res, "NDJSON line is not an object");
                }
                cJSON_Delete(item);
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    return 0;
}

static enum MHD_Result handle_ingest(siem_server *srv, struct MHD_Connection *conn,
                                     const char *body) {
    ingest_result res;
    memset(&res, 0, sizeof res);
    if (ingest_document(srv, body, &res) != 0) {
        return send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot parse body");
    }
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "accepted", res.accepted);
    cJSON_AddNumberToObject(resp, "duplicates", res.duplicates);
    cJSON_AddNumberToObject(resp, "alerts", res.alerts);
    cJSON_AddNumberToObject(resp, "rejected", res.rejected);
    cJSON *errs = cJSON_CreateArray();
    for (int i = 0; i < res.error_count; i++) {
        cJSON_AddItemToArray(errs, cJSON_CreateString(res.errors[i]));
        free(res.errors[i]);
    }
    cJSON_AddItemToObject(resp, "errors", errs);
    unsigned int status = (res.accepted == 0 && res.rejected > 0)
                              ? MHD_HTTP_BAD_REQUEST : MHD_HTTP_OK;
    enum MHD_Result rc = send_json(conn, status, resp);
    cJSON_Delete(resp);
    return rc;
}

static int append_body(request_ctx *ctx, const char *data, size_t size) {
    if (ctx->too_large) return 0;
    if (size > MAX_BODY || ctx->len > MAX_BODY - size) {
        ctx->too_large = 1;
        return 0;
    }
    char *next = realloc(ctx->body, ctx->len + size + 1);
    if (!next) {
        ctx->too_large = 1;
        return 0;
    }
    ctx->body = next;
    memcpy(ctx->body + ctx->len, data, size);
    ctx->len += size;
    ctx->body[ctx->len] = '\0';
    return 1;
}

static enum MHD_Result route(siem_server *srv, struct MHD_Connection *conn,
                             const char *url, const char *method, request_ctx *ctx) {
    if (strcmp(method, "GET") == 0 && strcmp(url, "/healthz") == 0) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "status", "ok");
        cJSON_AddStringToObject(obj, "version", QA_SIEM_VERSION);
        cJSON_AddNumberToObject(obj, "uptime_s", (double)(time(NULL) - srv->started));
        enum MHD_Result rc = send_json(conn, MHD_HTTP_OK, obj);
        cJSON_Delete(obj);
        return rc;
    }
    if (strcmp(method, "GET") == 0 && strcmp(url, "/") == 0) {
        return serve_static(srv, conn, "index.html", "text/html; charset=utf-8");
    }
    if (strcmp(method, "GET") == 0 && strcmp(url, "/app.js") == 0) {
        return serve_static(srv, conn, "app.js", "application/javascript; charset=utf-8");
    }
    if (strcmp(method, "GET") == 0 && strcmp(url, "/style.css") == 0) {
        return serve_static(srv, conn, "style.css", "text/css; charset=utf-8");
    }

    int protected = strcmp(url, "/ingest") == 0 ||
                    strncmp(url, "/api/", 5) == 0;
    if (protected && !authorized(srv, conn)) {
        return send_unauthorized(conn);
    }

    if (strcmp(method, "POST") == 0 && strcmp(url, "/ingest") == 0) {
        if (ctx->too_large) return send_error(conn, MHD_HTTP_CONTENT_TOO_LARGE,
                                              "request body too large");
        return handle_ingest(srv, conn, ctx->body ? ctx->body : "");
    }
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/v1/stats") == 0) {
        return handle_stats(srv, conn);
    }
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/v1/events") == 0) {
        return handle_events(srv, conn);
    }
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/v1/alerts") == 0) {
        return handle_alerts(srv, conn);
    }
    if (strcmp(method, "POST") == 0 && strcmp(url, "/api/v1/alerts/ack") == 0) {
        if (ctx->too_large) return send_error(conn, MHD_HTTP_CONTENT_TOO_LARGE,
                                              "request body too large");
        return handle_ack(srv, conn, ctx->body ? ctx->body : "");
    }
    return send_error(conn, MHD_HTTP_NOT_FOUND, "not found");
}

static enum MHD_Result handler(void *cls, struct MHD_Connection *conn,
                               const char *url, const char *method,
                               const char *version, const char *upload_data,
                               size_t *upload_data_size, void **con_cls) {
    (void)version;
    siem_server *srv = cls;
    request_ctx *ctx = *con_cls;
    if (!ctx) {
        ctx = calloc(1, sizeof(*ctx));
        if (!ctx) return MHD_NO;
        *con_cls = ctx;
        return MHD_YES;
    }
    if (*upload_data_size != 0) {
        append_body(ctx, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }
    if (ctx->done) return MHD_YES;
    ctx->done = 1;
    enum MHD_Result rc = route(srv, conn, url, method, ctx);
    return rc;
}

static int parse_bind(const char *bind, int port, struct sockaddr_storage *ss,
                      socklen_t *ss_len, char **err) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(bind && *bind ? bind : NULL, NULL, &hints, &res);
    if (rc != 0) {
        if (err) {
            char b[256];
            snprintf(b, sizeof b, "bind address %s: %s", bind, gai_strerror(rc));
            *err = xstrdup(b);
        }
        return -1;
    }
    if (!res || res->ai_addrlen > sizeof(*ss)) {
        freeaddrinfo(res);
        if (err) *err = xstrdup("unsupported bind address");
        return -1;
    }
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *ss_len = (socklen_t)res->ai_addrlen;
    if (ss->ss_family == AF_INET) {
        ((struct sockaddr_in *)ss)->sin_port = htons((uint16_t)port);
    } else if (ss->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)ss)->sin6_port = htons((uint16_t)port);
    }
    freeaddrinfo(res);
    return 0;
}

struct MHD_Daemon *server_start(siem_server *srv, const char *bind, int port,
                                const char *tls_cert, const char *tls_key,
                                char **err) {
    if (err) *err = NULL;
    srv->started = time(NULL);
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (bind && *bind && parse_bind(bind, port, &addr, &addr_len, err) != 0) {
        return NULL;
    }
    unsigned int flags = MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG;
    if (tls_cert && tls_key) flags |= MHD_USE_TLS;

    if (tls_cert && tls_key) {
        srv->tls_cert_mem = read_file(tls_cert, 1024 * 1024, err);
        srv->tls_key_mem = read_file(tls_key, 1024 * 1024, err);
        if (!srv->tls_cert_mem || !srv->tls_key_mem) return NULL;
    }

    struct MHD_Daemon *daemon;
    if (bind && *bind) {
        if (tls_cert && tls_key) {
            daemon = MHD_start_daemon(
                flags, (uint16_t)port, NULL, NULL, handler, srv,
                MHD_OPTION_SOCK_ADDR, (struct sockaddr *)&addr,
                MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,
                MHD_OPTION_CONNECTION_LIMIT, (unsigned int)64,
                MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int)16,
                MHD_OPTION_THREAD_POOL_SIZE, (unsigned int)4,
                MHD_OPTION_HTTPS_MEM_CERT, srv->tls_cert_mem,
                MHD_OPTION_HTTPS_MEM_KEY, srv->tls_key_mem,
                MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
                MHD_OPTION_END);
        } else {
            daemon = MHD_start_daemon(
                flags, (uint16_t)port, NULL, NULL, handler, srv,
                MHD_OPTION_SOCK_ADDR, (struct sockaddr *)&addr,
                MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,
                MHD_OPTION_CONNECTION_LIMIT, (unsigned int)64,
                MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int)16,
                MHD_OPTION_THREAD_POOL_SIZE, (unsigned int)4,
                MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
                MHD_OPTION_END);
        }
    } else if (tls_cert && tls_key) {
        daemon = MHD_start_daemon(
            flags, (uint16_t)port, NULL, NULL, handler, srv,
            MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,
            MHD_OPTION_CONNECTION_LIMIT, (unsigned int)64,
            MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int)16,
            MHD_OPTION_THREAD_POOL_SIZE, (unsigned int)4,
            MHD_OPTION_HTTPS_MEM_CERT, srv->tls_cert_mem,
            MHD_OPTION_HTTPS_MEM_KEY, srv->tls_key_mem,
            MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
            MHD_OPTION_END);
    } else {
        daemon = MHD_start_daemon(
            flags, (uint16_t)port, NULL, NULL, handler, srv,
            MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)30,
            MHD_OPTION_CONNECTION_LIMIT, (unsigned int)64,
            MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int)16,
            MHD_OPTION_THREAD_POOL_SIZE, (unsigned int)4,
            MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
            MHD_OPTION_END);
    }
    if (!daemon && err && !*err) *err = xstrdup("MHD_start_daemon failed");
    (void)addr_len;
    return daemon;
}

void server_stop(struct MHD_Daemon *daemon) {
    if (daemon) MHD_stop_daemon(daemon);
}
