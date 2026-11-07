#include "rules.h"

#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *dup_string(const cJSON *item) {
    if (!cJSON_IsString(item) || !item->valuestring) return NULL;
    return xstrdup(item->valuestring);
}

static void free_strings(char **items, int count) {
    if (!items) return;
    for (int i = 0; i < count; i++) free(items[i]);
    free(items);
}

static int load_string_array(const cJSON *root, const char *key, char ***out, int *count) {
    *out = NULL;
    *count = 0;
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!arr) return 0;
    if (!cJSON_IsArray(arr)) return -1;
    int n = cJSON_GetArraySize(arr);
    if (n <= 0) return 0;
    char **items = calloc((size_t)n, sizeof(*items));
    if (!items) return -1;
    int used = 0;
    const cJSON *it = NULL;
    cJSON_ArrayForEach(it, arr) {
        char *s = dup_string(it);
        if (!s) {
            free_strings(items, used);
            return -1;
        }
        items[used++] = s;
    }
    *out = items;
    *count = used;
    return 0;
}

void rules_init_defaults(siem_rules *rules) {
    memset(rules, 0, sizeof(*rules));
    rules->alert_severities = calloc(2, sizeof(char *));
    rules->alert_severities[0] = xstrdup("critical");
    rules->alert_severities[1] = xstrdup("error");
    rules->alert_count = 2;
    rules->thresholds = calloc(2, sizeof(threshold_rule));
    rules->thresholds[0].name = xstrdup("repeated-error");
    rules->thresholds[0].field = xstrdup("severity");
    rules->thresholds[0].value = xstrdup("error");
    rules->thresholds[0].count = 3;
    rules->thresholds[0].window_s = 300;
    rules->thresholds[0].severity = xstrdup("error");
    rules->thresholds[0].detail = xstrdup("Repeated error from the same source");
    rules->thresholds[1].name = xstrdup("repeated-warning");
    rules->thresholds[1].field = xstrdup("severity");
    rules->thresholds[1].value = xstrdup("warning");
    rules->thresholds[1].count = 5;
    rules->thresholds[1].window_s = 600;
    rules->thresholds[1].severity = xstrdup("warning");
    rules->thresholds[1].detail = xstrdup("Repeated warning from the same source");
    rules->threshold_count = 2;
}

void rules_free(siem_rules *rules) {
    if (!rules) return;
    free_strings(rules->alert_severities, rules->alert_count);
    free_strings(rules->ignore_rules, rules->ignore_count);
    for (int i = 0; i < rules->threshold_count; i++) {
        threshold_rule *r = &rules->thresholds[i];
        free(r->name);
        free(r->field);
        free(r->value);
        free(r->severity);
        free(r->detail);
    }
    free(rules->thresholds);
    memset(rules, 0, sizeof(*rules));
}

int rules_load_json(const char *json, siem_rules *rules, char **err) {
    if (err) *err = NULL;
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        if (err) *err = xstrdup("rules JSON could not be parsed");
        return -1;
    }
    siem_rules next;
    memset(&next, 0, sizeof(next));
    if (load_string_array(root, "alert_on_severities", &next.alert_severities,
                          &next.alert_count) != 0 ||
        load_string_array(root, "ignore_rules", &next.ignore_rules,
                          &next.ignore_count) != 0) {
        cJSON_Delete(root);
        rules_free(&next);
        if (err) *err = xstrdup("rules arrays must contain strings");
        return -1;
    }
    const cJSON *thresholds = cJSON_GetObjectItemCaseSensitive(root, "thresholds");
    if (thresholds) {
        if (!cJSON_IsArray(thresholds)) {
            cJSON_Delete(root);
            rules_free(&next);
            if (err) *err = xstrdup("thresholds must be an array");
            return -1;
        }
        int n = cJSON_GetArraySize(thresholds);
        if (n > 0) {
            next.thresholds = calloc((size_t)n, sizeof(threshold_rule));
            if (!next.thresholds) {
                cJSON_Delete(root);
                rules_free(&next);
                if (err) *err = xstrdup("out of memory");
                return -1;
            }
        }
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, thresholds) {
            if (!cJSON_IsObject(it)) continue;
            const cJSON *name = cJSON_GetObjectItemCaseSensitive(it, "name");
            const cJSON *match = cJSON_GetObjectItemCaseSensitive(it, "match");
            const cJSON *count = cJSON_GetObjectItemCaseSensitive(it, "count");
            const cJSON *window = cJSON_GetObjectItemCaseSensitive(it, "window_s");
            const cJSON *severity = cJSON_GetObjectItemCaseSensitive(it, "severity");
            const cJSON *detail = cJSON_GetObjectItemCaseSensitive(it, "detail");
            if (!cJSON_IsObject(match)) continue;
            const cJSON *field = NULL;
            const char *field_name = NULL;
            static const char *allowed[] = {"severity", "event_type", "source", "rule"};
            for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
                field = cJSON_GetObjectItemCaseSensitive(match, allowed[i]);
                if (cJSON_IsString(field)) {
                    field_name = allowed[i];
                    break;
                }
            }
            if (!field_name) continue;
            threshold_rule *r = &next.thresholds[next.threshold_count++];
            r->name = dup_string(name);
            r->field = xstrdup(field_name);
            r->value = dup_string(field);
            r->count = cJSON_IsNumber(count) ? count->valueint : 3;
            r->window_s = cJSON_IsNumber(window) ? window->valueint : 300;
            r->severity = dup_string(severity);
            r->detail = dup_string(detail);
            if (!r->name) r->name = xstrdup("threshold");
            if (!r->severity) {
                r->severity = xstrdup("warning");
            }
            if (r->count < 1) r->count = 1;
            if (r->window_s < 30) r->window_s = 30;
            if (!r->detail) r->detail = xstrdup("Threshold exceeded");
        }
    }
    cJSON_Delete(root);
    if (next.alert_count == 0) {
        next.alert_severities = calloc(2, sizeof(char *));
        next.alert_severities[0] = xstrdup("critical");
        next.alert_severities[1] = xstrdup("error");
        next.alert_count = 2;
    }
    rules_free(rules);
    *rules = next;
    return 0;
}

int rules_load_file(const char *path, siem_rules *rules, char **err) {
    if (!path || !*path) {
        rules_init_defaults(rules);
        return 0;
    }
    char *read_err = NULL;
    char *text = read_file(path, 1024 * 1024, &read_err);
    if (!text) {
        rules_init_defaults(rules);
        if (err) *err = read_err;
        return 1;
    }
    int rc = rules_load_json(text, rules, err);
    free(text);
    return rc;
}

int rules_alert_on_severity(const siem_rules *rules, const char *severity) {
    if (!rules || !severity) return 0;
    for (int i = 0; i < rules->alert_count; i++) {
        if (strcasecmp(rules->alert_severities[i], severity) == 0) return 1;
    }
    return 0;
}

int rules_ignored(const siem_rules *rules, const char *rule) {
    if (!rules || !rule) return 0;
    for (int i = 0; i < rules->ignore_count; i++) {
        if (strcmp(rules->ignore_rules[i], rule) == 0) return 1;
    }
    return 0;
}

static const char *event_field(cJSON *event, const char *field) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(event, field);
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

int rules_threshold_match(const threshold_rule *rule, cJSON *event) {
    if (!rule || !rule->field || !rule->value) return 0;
    const char *actual = event_field(event, rule->field);
    if (!actual) return 0;
    return strcasecmp(actual, rule->value) == 0;
}
