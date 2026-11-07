#include "db.h"
#include "rules.h"
#include "util.h"

#include <cjson/cJSON.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static cJSON *event(const char *id, const char *severity, const char *status) {
    char ts[32];
    iso_now(ts, sizeof ts);
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "event_id", id);
    cJSON_AddStringToObject(e, "ts", ts);
    cJSON_AddStringToObject(e, "host_id", "host-test");
    cJSON_AddStringToObject(e, "event_type", "finding");
    cJSON_AddStringToObject(e, "source", "test");
    cJSON_AddStringToObject(e, "rule", "test.rule");
    cJSON_AddStringToObject(e, "severity", severity);
    cJSON_AddStringToObject(e, "status", status);
    cJSON_AddStringToObject(e, "subject", "test-subject");
    cJSON_AddStringToObject(e, "detail", "test detail");
    cJSON_AddStringToObject(e, "fingerprint", "fp-1");
    return e;
}

int main(void) {
    char path[] = "/tmp/qa-siem-test-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unlink(path);

    siem_db db;
    char *err = NULL;
    assert(db_open(&db, path, &err) == 0);

    siem_rules rules;
    memset(&rules, 0, sizeof rules);
    rules_init_defaults(&rules);

    cJSON *e1 = event("evt-1", "error", "open");
    int inserted = 0, alerted = 0;
    assert(db_ingest(&db, &rules, e1, &err, &inserted, &alerted) == 0);
    assert(inserted == 1);
    assert(alerted >= 1);
    cJSON_Delete(e1);

    cJSON *dup = event("evt-1", "error", "open");
    assert(db_ingest(&db, &rules, dup, &err, &inserted, &alerted) == 0);
    assert(inserted == 0);
    cJSON_Delete(dup);

    cJSON *e2 = event("evt-2", "error", "resolved");
    assert(db_ingest(&db, &rules, e2, &err, &inserted, &alerted) == 0);
    assert(inserted == 1);
    cJSON_Delete(e2);

    cJSON *stats = NULL;
    assert(db_stats(&db, &stats, &err) == 0);
    cJSON *events = cJSON_GetObjectItemCaseSensitive(stats, "events");
    cJSON *open = cJSON_GetObjectItemCaseSensitive(stats, "alerts_open");
    assert(cJSON_IsNumber(events) && events->valueint == 2);
    assert(cJSON_IsNumber(open) && open->valueint == 0);
    cJSON_Delete(stats);

    cJSON *list = NULL;
    assert(db_events(&db, NULL, "error", NULL, 10, &list, &err) == 0);
    assert(cJSON_IsArray(list) && cJSON_GetArraySize(list) == 2);
    cJSON_Delete(list);

    cJSON *alerts = NULL;
    assert(db_alerts(&db, "resolved", 10, &alerts, &err) == 0);
    assert(cJSON_IsArray(alerts) && cJSON_GetArraySize(alerts) >= 1);
    cJSON_Delete(alerts);

    rules_free(&rules);
    db_close(&db);
    unlink(path);
    char wal[512], shm[512];
    snprintf(wal, sizeof wal, "%s-wal", path);
    snprintf(shm, sizeof shm, "%s-shm", path);
    unlink(wal);
    unlink(shm);
    printf("test_core: ok\n");
    return 0;
}
