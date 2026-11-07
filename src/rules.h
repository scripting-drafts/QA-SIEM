#ifndef QA_SIEM_RULES_H
#define QA_SIEM_RULES_H

#include <cjson/cJSON.h>

typedef struct {
    char *name;
    char *field;
    char *value;
    int count;
    int window_s;
    char *severity;
    char *detail;
} threshold_rule;

typedef struct {
    char **alert_severities;
    int alert_count;
    char **ignore_rules;
    int ignore_count;
    threshold_rule *thresholds;
    int threshold_count;
} siem_rules;

void rules_init_defaults(siem_rules *rules);
int rules_load_json(const char *json, siem_rules *rules, char **err);
int rules_load_file(const char *path, siem_rules *rules, char **err);
void rules_free(siem_rules *rules);
int rules_alert_on_severity(const siem_rules *rules, const char *severity);
int rules_ignored(const siem_rules *rules, const char *rule);
int rules_threshold_match(const threshold_rule *rule, cJSON *event);

#endif
