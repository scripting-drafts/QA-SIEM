#ifndef QA_SIEM_DB_H
#define QA_SIEM_DB_H

#include <cjson/cJSON.h>
#include <pthread.h>
#include <sqlite3.h>

#include "rules.h"

typedef struct {
    sqlite3 *conn;
    pthread_mutex_t lock;
    char *path;
} siem_db;

int db_open(siem_db *db, const char *path, char **err);
void db_close(siem_db *db);
int db_ingest(siem_db *db, const siem_rules *rules, cJSON *event,
              char **err, int *inserted, int *alerted);
int db_stats(siem_db *db, cJSON **out, char **err);
int db_events(siem_db *db, const char *since, const char *severity,
              const char *host_id, int limit, cJSON **out, char **err);
int db_alerts(siem_db *db, const char *status, int limit, cJSON **out, char **err);
int db_ack(siem_db *db, long id, char **err);
int db_cleanup(siem_db *db, int retention_days, char **err);

#endif
