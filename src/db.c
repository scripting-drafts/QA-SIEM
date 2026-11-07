#include "db.h"

#include "log.h"
#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_ID 256
#define MAX_TEXT 8192
#define MAX_PAYLOAD (1024 * 1024)

static void set_err(char **err, const char *fmt, ...) {
    if (!err) return;
    free(*err);
    *err = NULL;
    va_list ap;
    va_start(ap, fmt);
    char buf[512];
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    *err = xstrdup(buf);
}

static int exec_sql(siem_db *db, const char *sql, char **err) {
    char *sql_err = NULL;
    int rc = sqlite3_exec(db->conn, sql, NULL, NULL, &sql_err);
    if (rc != SQLITE_OK) {
        set_err(err, "%s", sql_err ? sql_err : sqlite3_errmsg(db->conn));
        sqlite3_free(sql_err);
        return -1;
    }
    return 0;
}

static const char *event_string(cJSON *event, const char *key) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(event, key);
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static char *lower_copy(const char *s) {
    if (!s) return NULL;
    char *out = xstrdup(s);
    if (!out) return NULL;
    for (char *p = out; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');
    }
    return out;
}

static int valid_severity(const char *s) {
    return strcmp(s, "critical") == 0 || strcmp(s, "error") == 0 ||
           strcmp(s, "warning") == 0 || strcmp(s, "info") == 0;
}

static int upsert_alert(siem_db *db, const char *key, const char *ts,
                        const char *host, const char *rule, const char *severity,
                        const char *subject, const char *detail, const char *event_id,
                        const char *fingerprint, char **err) {
    const char *sql =
        "INSERT INTO alerts(alert_key,ts,last_seen,host_id,rule,severity,subject,"
        "detail,status,count,event_id,fingerprint) VALUES(?,?,?,?,?,?,?,?, 'open',1,?,?) "
        "ON CONFLICT(alert_key) DO UPDATE SET "
        "last_seen=excluded.last_seen, count=alerts.count+1, "
        "severity=excluded.severity, subject=excluded.subject, detail=excluded.detail, "
        "event_id=excluded.event_id, "
        "status=CASE WHEN alerts.status='resolved' THEN 'open' ELSE alerts.status END";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        set_err(err, "prepare alert: %s", sqlite3_errmsg(db->conn));
        return -1;
    }
    int rc = SQLITE_OK;
    rc |= sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 2, ts, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 3, ts, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 4, host, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 5, rule, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 6, severity, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 7, subject, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 8, detail, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 9, event_id, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 10, fingerprint, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        set_err(err, "bind alert: %s", sqlite3_errmsg(db->conn));
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        set_err(err, "write alert: %s", sqlite3_errmsg(db->conn));
        return -1;
    }
    return 0;
}

static int resolve_alerts(siem_db *db, const char *ts, const char *host,
                          const char *rule, const char *fingerprint, char **err) {
    const char *sql =
        "UPDATE alerts SET status='resolved', resolved_ts=? "
        "WHERE host_id=? AND rule=? AND fingerprint=? AND status IN ('open','acked')";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        set_err(err, "prepare resolve: %s", sqlite3_errmsg(db->conn));
        return -1;
    }
    int rc = SQLITE_OK;
    rc |= sqlite3_bind_text(stmt, 1, ts, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 2, host, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 3, rule, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 4, fingerprint, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        set_err(err, "resolve alerts: %s", sqlite3_errmsg(db->conn));
        return -1;
    }
    return 0;
}

static int threshold_count(siem_db *db, cJSON *event, const threshold_rule *rule,
                           const char *host, const char *rule_name,
                           const char *fingerprint, int *count, char **err) {
    (void)event;
    char cutoff[32];
    iso_time(time(NULL) - rule->window_s, cutoff, sizeof cutoff);
    const char *sql =
        "SELECT COUNT(*) FROM events WHERE host_id=? AND rule=? AND fingerprint=? "
        "AND received_ts>=?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        set_err(err, "prepare threshold: %s", sqlite3_errmsg(db->conn));
        return -1;
    }
    int rc = SQLITE_OK;
    rc |= sqlite3_bind_text(stmt, 1, host, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 2, rule_name, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 3, fingerprint, -1, SQLITE_TRANSIENT);
    rc |= sqlite3_bind_text(stmt, 4, cutoff, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        *count = sqlite3_column_int(stmt, 0);
    } else {
        set_err(err, "count threshold: %s", sqlite3_errmsg(db->conn));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int db_ingest(siem_db *db, const siem_rules *rules, cJSON *event,
              char **err, int *inserted, int *alerted) {
    if (err) *err = NULL;
    *inserted = 0;
    *alerted = 0;
    if (!cJSON_IsObject(event)) {
        set_err(err, "event must be a JSON object");
        return -1;
    }
    const char *event_id = event_string(event, "event_id");
    const char *ts = event_string(event, "ts");
    if (!event_id || !*event_id || strlen(event_id) > MAX_ID) {
        set_err(err, "event_id is required and must be <= %d bytes", MAX_ID);
        return -1;
    }
    if (!ts || !*ts || strlen(ts) > 64) {
        set_err(err, "ts is required and must be <= 64 bytes");
        return -1;
    }
    const char *host = event_string(event, "host_id");
    if (!host || !*host) host = "unknown";
    const char *event_type = event_string(event, "event_type");
    if (!event_type || !*event_type) event_type = "event";
    const char *source = event_string(event, "source");
    if (!source) source = "";
    const char *rule = event_string(event, "rule");
    if (!rule) rule = "";
    const char *subject = event_string(event, "subject");
    if (!subject) subject = rule;
    const char *detail = event_string(event, "detail");
    if (!detail) detail = "";
    const char *status = event_string(event, "status");
    if (!status || !*status) status = "open";
    const char *fingerprint = event_string(event, "fingerprint");
    if (!fingerprint || !*fingerprint) fingerprint = event_id;

    if (strlen(host) > MAX_ID || strlen(event_type) > MAX_ID ||
        strlen(source) > MAX_ID || strlen(rule) > MAX_ID ||
        strlen(subject) > MAX_TEXT || strlen(detail) > MAX_TEXT ||
        strlen(fingerprint) > MAX_ID || strlen(status) > 32) {
        set_err(err, "event field exceeds size limit");
        return -1;
    }

    char *sev = lower_copy(event_string(event, "severity"));
    if (!sev || !*sev) {
        free(sev);
        sev = xstrdup("info");
    } else if (!valid_severity(sev)) {
        set_err(err, "invalid severity: %s", sev);
        free(sev);
        return -1;
    }

    char *tags = NULL;
    const cJSON *tag_item = cJSON_GetObjectItemCaseSensitive(event, "tags");
    if (tag_item) {
        tags = cJSON_PrintUnformatted(tag_item);
    }
    if (!tags) tags = xstrdup("[]");
    char *payload = cJSON_PrintUnformatted(event);
    if (!payload || strlen(payload) > MAX_PAYLOAD) {
        set_err(err, "event payload is too large");
        free(sev);
        free(tags);
        free(payload);
        return -1;
    }

    char received[32];
    iso_now(received, sizeof received);
    pthread_mutex_lock(&db->lock);
    if (exec_sql(db, "BEGIN IMMEDIATE", err) != 0) {
        pthread_mutex_unlock(&db->lock);
        free(sev); free(tags); free(payload);
        return -1;
    }

    const char *ins =
        "INSERT OR IGNORE INTO events(event_id,ts,received_ts,host_id,event_type,"
        "source,rule,severity,status,subject,detail,fingerprint,tags,payload) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db->conn, ins, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        set_err(err, "prepare event: %s", sqlite3_errmsg(db->conn));
        exec_sql(db, "ROLLBACK", NULL);
        pthread_mutex_unlock(&db->lock);
        free(sev); free(tags); free(payload);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ts, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, received, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, host, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, event_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, rule, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, sev, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, subject, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, detail, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, tags, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, payload, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        set_err(err, "insert event: %s", sqlite3_errmsg(db->conn));
        exec_sql(db, "ROLLBACK", NULL);
        pthread_mutex_unlock(&db->lock);
        free(sev); free(tags); free(payload);
        return -1;
    }
    *inserted = sqlite3_changes(db->conn) > 0;

    if (*inserted) {
        if (strcasecmp(status, "resolved") == 0) {
            if (resolve_alerts(db, ts, host, rule, fingerprint, err) != 0) {
                exec_sql(db, "ROLLBACK", NULL);
                pthread_mutex_unlock(&db->lock);
                free(sev); free(tags); free(payload);
                return -1;
            }
        } else {
            if (rules_alert_on_severity(rules, sev) && !rules_ignored(rules, rule)) {
                char key[1024];
                snprintf(key, sizeof key, "severity|%s|%s|%s", rule, host, fingerprint);
                if (upsert_alert(db, key, ts, host, rule, sev, subject, detail,
                                 event_id, fingerprint, err) != 0) {
                    exec_sql(db, "ROLLBACK", NULL);
                    pthread_mutex_unlock(&db->lock);
                    free(sev); free(tags); free(payload);
                    return -1;
                }
                (*alerted)++;
            }
            for (int i = 0; i < rules->threshold_count; i++) {
                const threshold_rule *tr = &rules->thresholds[i];
                if (!rules_threshold_match(tr, event)) continue;
                int count = 0;
                if (threshold_count(db, event, tr, host, rule, fingerprint, &count, err) != 0) {
                    exec_sql(db, "ROLLBACK", NULL);
                    pthread_mutex_unlock(&db->lock);
                    free(sev); free(tags); free(payload);
                    return -1;
                }
                if (count < tr->count) continue;
                char key[1024];
                snprintf(key, sizeof key, "threshold|%s|%s|%s", tr->name, host, rule);
                char threshold_detail[MAX_TEXT];
                snprintf(threshold_detail, sizeof threshold_detail,
                         "%s (count=%d, window=%ds)", tr->detail ? tr->detail : "Threshold exceeded",
                         count, tr->window_s);
                if (upsert_alert(db, key, ts, host, rule, tr->severity, subject,
                                 threshold_detail, event_id, fingerprint, err) != 0) {
                    exec_sql(db, "ROLLBACK", NULL);
                    pthread_mutex_unlock(&db->lock);
                    free(sev); free(tags); free(payload);
                    return -1;
                }
                (*alerted)++;
            }
        }
    }

    if (exec_sql(db, "COMMIT", err) != 0) {
        pthread_mutex_unlock(&db->lock);
        free(sev); free(tags); free(payload);
        return -1;
    }
    pthread_mutex_unlock(&db->lock);
    free(sev);
    free(tags);
    free(payload);
    return 0;
}

int db_open(siem_db *db, const char *path, char **err) {
    if (err) *err = NULL;
    memset(db, 0, sizeof(*db));
    db->path = xstrdup(path);
    if (sqlite3_open_v2(path, &db->conn, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)
        != SQLITE_OK) {
        set_err(err, "open database: %s", sqlite3_errmsg(db->conn));
        sqlite3_close(db->conn);
        db->conn = NULL;
        free(db->path);
        db->path = NULL;
        return -1;
    }
    pthread_mutex_init(&db->lock, NULL);
    sqlite3_busy_timeout(db->conn, 5000);
    const char *schema =
        "PRAGMA journal_mode=WAL;"
        "PRAGMA synchronous=NORMAL;"
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS events("
        "id INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,ts TEXT NOT NULL,"
        "received_ts TEXT NOT NULL,host_id TEXT NOT NULL,event_type TEXT NOT NULL,"
        "source TEXT,rule TEXT,severity TEXT,status TEXT,subject TEXT,detail TEXT,"
        "fingerprint TEXT,tags TEXT,payload TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);"
        "CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_ts);"
        "CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule,host_id,fingerprint);"
        "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity,ts);"
        "CREATE TABLE IF NOT EXISTS alerts("
        "id INTEGER PRIMARY KEY,alert_key TEXT UNIQUE NOT NULL,ts TEXT NOT NULL,"
        "last_seen TEXT NOT NULL,host_id TEXT,rule TEXT,severity TEXT,subject TEXT,"
        "detail TEXT,status TEXT NOT NULL DEFAULT 'open',count INTEGER NOT NULL DEFAULT 1,"
        "event_id TEXT,fingerprint TEXT,acked_ts TEXT,resolved_ts TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status,last_seen);"
        "CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule,host_id);";
    if (exec_sql(db, schema, err) != 0) {
        db_close(db);
        return -1;
    }
    return 0;
}

void db_close(siem_db *db) {
    if (!db) return;
    if (db->conn) {
        sqlite3_close(db->conn);
        db->conn = NULL;
    }
    pthread_mutex_destroy(&db->lock);
    free(db->path);
    db->path = NULL;
}

int db_stats(siem_db *db, cJSON **out, char **err) {
    if (err) *err = NULL;
    pthread_mutex_lock(&db->lock);
    cJSON *root = cJSON_CreateObject();
    const char *queries[] = {
        "SELECT COUNT(*) FROM events",
        "SELECT COUNT(*) FROM alerts WHERE status='open'",
        "SELECT COUNT(*) FROM alerts",
        "SELECT COUNT(DISTINCT host_id) FROM events",
    };
    const char *keys[] = {"events", "alerts_open", "alerts_total", "hosts"};
    for (int i = 0; i < 4; i++) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db->conn, queries[i], -1, &stmt, NULL) != SQLITE_OK ||
            sqlite3_step(stmt) != SQLITE_ROW) {
            set_err(err, "stats query failed: %s", sqlite3_errmsg(db->conn));
            sqlite3_finalize(stmt);
            cJSON_Delete(root);
            pthread_mutex_unlock(&db->lock);
            return -1;
        }
        cJSON_AddNumberToObject(root, keys[i], sqlite3_column_int(stmt, 0));
        sqlite3_finalize(stmt);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->conn,
            "SELECT MAX(ts) FROM events", -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *last = sqlite3_column_text(stmt, 0);
        cJSON_AddStringToObject(root, "last_event_ts",
                                last ? (const char *)last : "");
    } else {
        cJSON_AddStringToObject(root, "last_event_ts", "");
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db->lock);
    *out = root;
    return 0;
}

static void add_text_column(cJSON *obj, sqlite3_stmt *stmt, int col, const char *key) {
    const unsigned char *s = sqlite3_column_text(stmt, col);
    cJSON_AddStringToObject(obj, key, s ? (const char *)s : "");
}

int db_events(siem_db *db, const char *since, const char *severity,
              const char *host_id, int limit, cJSON **out, char **err) {
    if (err) *err = NULL;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;
    char sql[1024] = "SELECT id,event_id,ts,received_ts,host_id,event_type,source,rule,"
                     "severity,status,subject,detail,fingerprint,tags FROM events";
    int nwhere = 0;
    if (since && *since) {
        strncat(sql, nwhere++ ? " AND" : " WHERE", sizeof sql - strlen(sql) - 1);
        strncat(sql, " ts>=?", sizeof sql - strlen(sql) - 1);
    }
    if (severity && *severity) {
        strncat(sql, nwhere++ ? " AND" : " WHERE", sizeof sql - strlen(sql) - 1);
        strncat(sql, " severity=?", sizeof sql - strlen(sql) - 1);
    }
    if (host_id && *host_id) {
        strncat(sql, nwhere++ ? " AND" : " WHERE", sizeof sql - strlen(sql) - 1);
        strncat(sql, " host_id=?", sizeof sql - strlen(sql) - 1);
    }
    strncat(sql, " ORDER BY id DESC LIMIT ?", sizeof sql - strlen(sql) - 1);

    pthread_mutex_lock(&db->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        set_err(err, "prepare events: %s", sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }
    int idx = 1;
    if (since && *since) sqlite3_bind_text(stmt, idx++, since, -1, SQLITE_TRANSIENT);
    if (severity && *severity) sqlite3_bind_text(stmt, idx++, severity, -1, SQLITE_TRANSIENT);
    if (host_id && *host_id) sqlite3_bind_text(stmt, idx++, host_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx, limit);
    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id", sqlite3_column_int(stmt, 0));
        add_text_column(obj, stmt, 1, "event_id");
        add_text_column(obj, stmt, 2, "ts");
        add_text_column(obj, stmt, 3, "received_ts");
        add_text_column(obj, stmt, 4, "host_id");
        add_text_column(obj, stmt, 5, "event_type");
        add_text_column(obj, stmt, 6, "source");
        add_text_column(obj, stmt, 7, "rule");
        add_text_column(obj, stmt, 8, "severity");
        add_text_column(obj, stmt, 9, "status");
        add_text_column(obj, stmt, 10, "subject");
        add_text_column(obj, stmt, 11, "detail");
        add_text_column(obj, stmt, 12, "fingerprint");
        add_text_column(obj, stmt, 13, "tags");
        cJSON_AddItemToArray(arr, obj);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db->lock);
    *out = arr;
    return 0;
}

int db_alerts(siem_db *db, const char *status, int limit, cJSON **out, char **err) {
    if (err) *err = NULL;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;
    char sql[512] = "SELECT id,ts,last_seen,host_id,rule,severity,subject,detail,"
                    "status,count,event_id,fingerprint,acked_ts,resolved_ts FROM alerts";
    if (status && *status) strncat(sql, " WHERE status=?", sizeof sql - strlen(sql) - 1);
    strncat(sql, " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'error' THEN 1 "
                 "WHEN 'warning' THEN 2 ELSE 3 END, last_seen DESC LIMIT ?",
            sizeof sql - strlen(sql) - 1);
    pthread_mutex_lock(&db->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        set_err(err, "prepare alerts: %s", sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }
    int idx = 1;
    if (status && *status) sqlite3_bind_text(stmt, idx++, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx, limit);
    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id", sqlite3_column_int(stmt, 0));
        add_text_column(obj, stmt, 1, "ts");
        add_text_column(obj, stmt, 2, "last_seen");
        add_text_column(obj, stmt, 3, "host_id");
        add_text_column(obj, stmt, 4, "rule");
        add_text_column(obj, stmt, 5, "severity");
        add_text_column(obj, stmt, 6, "subject");
        add_text_column(obj, stmt, 7, "detail");
        add_text_column(obj, stmt, 8, "status");
        cJSON_AddNumberToObject(obj, "count", sqlite3_column_int(stmt, 9));
        add_text_column(obj, stmt, 10, "event_id");
        add_text_column(obj, stmt, 11, "fingerprint");
        add_text_column(obj, stmt, 12, "acked_ts");
        add_text_column(obj, stmt, 13, "resolved_ts");
        cJSON_AddItemToArray(arr, obj);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db->lock);
    *out = arr;
    return 0;
}

int db_ack(siem_db *db, long id, char **err) {
    if (err) *err = NULL;
    char ts[32];
    iso_now(ts, sizeof ts);
    pthread_mutex_lock(&db->lock);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE alerts SET status='acked', acked_ts=? "
                      "WHERE id=? AND status='open'";
    if (sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        set_err(err, "prepare ack: %s", sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, ts, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    int changed = sqlite3_changes(db->conn);
    pthread_mutex_unlock(&db->lock);
    if (rc != SQLITE_DONE) {
        set_err(err, "ack failed: %s", sqlite3_errmsg(db->conn));
        return -1;
    }
    if (changed == 0) {
        set_err(err, "alert not found or not open");
        return 1;
    }
    return 0;
}

int db_cleanup(siem_db *db, int retention_days, char **err) {
    if (err) *err = NULL;
    if (retention_days < 1) retention_days = 30;
    char cutoff[32];
    iso_time(time(NULL) - (time_t)retention_days * 86400, cutoff, sizeof cutoff);
    pthread_mutex_lock(&db->lock);
    sqlite3_stmt *stmt = NULL;
    int deleted_events = 0;
    int deleted_alerts = 0;
    if (sqlite3_prepare_v2(db->conn, "DELETE FROM events WHERE received_ts<?",
                           -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, cutoff, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE) deleted_events = sqlite3_changes(db->conn);
        sqlite3_finalize(stmt);
    }
    if (sqlite3_prepare_v2(db->conn,
            "DELETE FROM alerts WHERE status IN ('resolved','acked') AND last_seen<?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, cutoff, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE) deleted_alerts = sqlite3_changes(db->conn);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&db->lock);
    log_info("retention cleanup: events=%d alerts=%d cutoff=%s",
             deleted_events, deleted_alerts, cutoff);
    return 0;
}
