#include "db.h"
#include "log.h"
#include "rules.h"
#include "server.h"
#include "util.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

static void on_signal(int sig) {
    (void)sig;
    stop_requested = 1;
}

static void usage(FILE *out) {
    fprintf(out,
        "qa-siem %s\n"
        "Usage: qa-siem [options]\n"
        "  --db PATH             SQLite database (default /var/lib/qa-siem/siem.db)\n"
        "  --bind ADDR           listen address (default 127.0.0.1)\n"
        "  --port N              listen port (default 8088)\n"
        "  --token-file PATH     bearer token file (default /etc/qa-siem/token)\n"
        "  --rules PATH          detection rules JSON\n"
        "  --web-root PATH       dashboard directory\n"
        "  --retention-days N    event retention (default 30)\n"
        "  --tls-cert PATH       TLS certificate (PEM)\n"
        "  --tls-key PATH        TLS private key (PEM)\n"
        "  --allow-no-auth       allow unauthenticated ingest/API (loopback only)\n"
        "  --allow-plaintext     allow non-loopback without TLS (not recommended)\n"
        "  --check               validate configuration and exit\n"
        "  --version             print version\n"
        "  --help                this text\n",
        QA_SIEM_VERSION);
}

static char *read_token(const char *path, char **err) {
    if (err) *err = NULL;
    char *text = read_file(path, 4096, err);
    if (!text) return NULL;
    char *token = trim_whitespace(text);
    if (!*token) {
        if (err) *err = xstrdup("token file is empty");
        free(text);
        return NULL;
    }
    struct stat st;
    if (stat(path, &st) == 0 && (st.st_mode & S_IROTH)) {
        log_warn("token file %s is world-readable; restrict it to 0640", path);
    }
    char *out = xstrdup(token);
    wipe_free(text);
    return out;
}

static int ensure_parent_dir(const char *path) {
    char *copy = xstrdup(path);
    if (!copy) return -1;
    char *slash = strrchr(copy, '/');
    if (slash && slash != copy) {
        *slash = '\0';
        if (mkdir(copy, 0750) != 0 && errno != EEXIST) {
            free(copy);
            return -1;
        }
    }
    free(copy);
    return 0;
}

static int web_root_ok(const char *root) {
    size_t n = strlen(root) + 16;
    char *path = malloc(n);
    if (!path) return 0;
    snprintf(path, n, "%s/index.html", root);
    struct stat st;
    int ok = stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0;
    free(path);
    return ok;
}

int main(int argc, char **argv) {
    const char *db_path = getenv("SIEM_DB");
    const char *bind = getenv("SIEM_BIND");
    const char *token_file = getenv("SIEM_TOKEN_FILE");
    const char *rules_path = getenv("SIEM_RULES");
    const char *web_root = getenv("SIEM_WEB_ROOT");
    const char *tls_cert = getenv("SIEM_TLS_CERT");
    const char *tls_key = getenv("SIEM_TLS_KEY");
    int port = parse_int_range(getenv("SIEM_PORT"), 8088, 1, 65535);
    int retention = parse_int_range(getenv("SIEM_RETENTION_DAYS"), 30, 1, 3650);
    int allow_no_auth = 0;
    int allow_plaintext = 0;
    int check_only = 0;

    if (!db_path || !*db_path) db_path = "/var/lib/qa-siem/siem.db";
    if (!bind || !*bind) bind = "127.0.0.1";
    if (!token_file || !*token_file) token_file = "/etc/qa-siem/token";
    if (!rules_path || !*rules_path) rules_path = "/etc/qa-siem/rules.json";
    if (!web_root || !*web_root) web_root = "/usr/share/qa-siem/web";

    static const struct option opts[] = {
        {"db", required_argument, NULL, 'd'},
        {"bind", required_argument, NULL, 'b'},
        {"port", required_argument, NULL, 'p'},
        {"token-file", required_argument, NULL, 't'},
        {"rules", required_argument, NULL, 'r'},
        {"web-root", required_argument, NULL, 'w'},
        {"retention-days", required_argument, NULL, 'R'},
        {"tls-cert", required_argument, NULL, 'c'},
        {"tls-key", required_argument, NULL, 'k'},
        {"allow-no-auth", no_argument, NULL, 'A'},
        {"allow-plaintext", no_argument, NULL, 'P'},
        {"check", no_argument, NULL, 'C'},
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "d:b:p:t:r:w:R:c:k:APCVh", opts, NULL)) != -1) {
        switch (opt) {
            case 'd': db_path = optarg; break;
            case 'b': bind = optarg; break;
            case 'p': port = parse_int_range(optarg, 0, 1, 65535); break;
            case 't': token_file = optarg; break;
            case 'r': rules_path = optarg; break;
            case 'w': web_root = optarg; break;
            case 'R': retention = parse_int_range(optarg, 0, 1, 3650); break;
            case 'c': tls_cert = optarg; break;
            case 'k': tls_key = optarg; break;
            case 'A': allow_no_auth = 1; break;
            case 'P': allow_plaintext = 1; break;
            case 'C': check_only = 1; break;
            case 'V': printf("qa-siem %s\n", QA_SIEM_VERSION); return 0;
            case 'h': usage(stdout); return 0;
            default: usage(stderr); return 2;
        }
    }
    if (port == 0) {
        fprintf(stderr, "invalid port\n");
        return 2;
    }
    if (retention == 0) {
        fprintf(stderr, "invalid retention\n");
        return 2;
    }
    if ((tls_cert && !tls_key) || (!tls_cert && tls_key)) {
        fprintf(stderr, "--tls-cert and --tls-key must be used together\n");
        return 2;
    }
    if (!is_loopback(bind) && !tls_cert && !allow_plaintext) {
        fprintf(stderr, "refusing plaintext HTTP on non-loopback bind %s; "
                        "use TLS or --allow-plaintext\n", bind);
        return 2;
    }
    if (allow_no_auth && !is_loopback(bind)) {
        fprintf(stderr, "--allow-no-auth is only allowed on a loopback bind\n");
        return 2;
    }
    if (!web_root_ok(web_root)) {
        fprintf(stderr, "web root is missing index.html: %s\n", web_root);
        return 2;
    }

    char *token = NULL;
    const char *env_token = getenv("SIEM_TOKEN");
    if (env_token && *env_token) {
        char *copy = xstrdup(env_token);
        if (copy) token = xstrdup(trim_whitespace(copy));
        free(copy);
        if (token && !*token) {
            wipe_free(token);
            token = NULL;
        }
    } else {
        char *err = NULL;
        token = read_token(token_file, &err);
        if (!token && !allow_no_auth) {
            fprintf(stderr, "cannot read token: %s\n", err ? err : "unknown");
            free(err);
            return 2;
        }
        free(err);
        if (!token && allow_no_auth) {
            log_warn("authentication disabled by --allow-no-auth");
        }
    }

    siem_rules rules;
    memset(&rules, 0, sizeof rules);
    char *rules_err = NULL;
    int rr = rules_load_file(rules_path, &rules, &rules_err);
    if (rr < 0) {
        fprintf(stderr, "rules: %s\n", rules_err ? rules_err : "invalid");
        free(rules_err);
        wipe_free(token);
        return 2;
    }
    if (rr > 0) {
        log_warn("using built-in rules: %s", rules_err ? rules_err : "no rules file");
    }
    free(rules_err);

    if (ensure_parent_dir(db_path) != 0) {
        fprintf(stderr, "cannot create database directory for %s\n", db_path);
        rules_free(&rules);
        wipe_free(token);
        return 2;
    }
    siem_db db;
    char *db_err = NULL;
    if (db_open(&db, db_path, &db_err) != 0) {
        fprintf(stderr, "database: %s\n", db_err ? db_err : "open failed");
        free(db_err);
        rules_free(&rules);
        wipe_free(token);
        return 2;
    }
    if (check_only) {
        printf("ok: db=%s bind=%s port=%d rules=%s tls=%s auth=%s\n",
               db_path, bind, port, rules_path, tls_cert ? "on" : "off",
               token ? "bearer" : "disabled");
        db_close(&db);
        rules_free(&rules);
        wipe_free(token);
        return 0;
    }

    db_cleanup(&db, retention, NULL);
    siem_server srv;
    memset(&srv, 0, sizeof srv);
    srv.db = &db;
    srv.rules = &rules;
    srv.token = token;
    srv.web_root = (char *)web_root;
    srv.retention_days = retention;
    srv.allow_no_auth = allow_no_auth;
    srv.started = time(NULL);

    char *server_err = NULL;
    struct MHD_Daemon *daemon = server_start(&srv, bind, port, tls_cert, tls_key,
                                             &server_err);
    if (!daemon) {
        fprintf(stderr, "server: %s\n", server_err ? server_err : "start failed");
        free(server_err);
        db_close(&db);
        rules_free(&rules);
        wipe_free(token);
        free(srv.tls_key_mem);
        free(srv.tls_cert_mem);
        return 1;
    }
    log_info("listening on %s:%d tls=%s auth=%s db=%s",
             bind, port, tls_cert ? "on" : "off", token ? "bearer" : "disabled", db_path);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    time_t last_cleanup = time(NULL);
    while (!stop_requested) {
        sleep(1);
        time_t now = time(NULL);
        if (now - last_cleanup >= 3600) {
            db_cleanup(&db, retention, NULL);
            last_cleanup = now;
        }
    }

    log_info("shutting down");
    server_stop(daemon);
    free(srv.tls_key_mem);
    free(srv.tls_cert_mem);
    db_close(&db);
    rules_free(&rules);
    wipe_free(token);
    return 0;
}
