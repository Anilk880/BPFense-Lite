#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_RULES 128
#define MAX_PODS 128

/* ---------------- STRUCTS ---------------- */

struct feature_rule {
    char event_type[16];
    char field[32];
    char value[64];
    char feature[64];
    int weight;
};

struct pod_feature {
    char pod[64];
    int file_access;
    int net;
    int exec;
    int sensitive_file;
};

/* ---------------- GLOBALS ---------------- */

static struct feature_rule rules[MAX_RULES];
static int rule_count = 0;

static struct pod_feature pod_stats[MAX_PODS];
static int pod_count = 0;

static void safe_copy(char *dst, const char *src, size_t size) {
    if (size == 0)
        return;

    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';   // ALWAYS null terminate
}

/* ---------------- UTIL ---------------- */

static void trim(char *str) {
    char *start = str;
    char *end;

    while (*start == ' ' || *start == '\t')
        start++;

    if (start != str)
        memmove(str, start, strlen(start) + 1);

    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\n' || *end == '\t'))
        *end-- = '\0';
}

/* ---------------- POD STORAGE ---------------- */

static struct pod_feature *get_pod_feature(const char *pod) {
    for (int i = 0; i < pod_count; i++) {
        if (strcmp(pod_stats[i].pod, pod) == 0)
            return &pod_stats[i];
    }

    if (pod_count < MAX_PODS) {
        struct pod_feature *pf = &pod_stats[pod_count];

        strncpy(pf->pod, pod, sizeof(pf->pod) - 1);
        pf->pod[sizeof(pf->pod) - 1] = '\0';

        pf->file_access = 0;
        pf->net = 0;
        pf->exec = 0;
        pf->sensitive_file = 0;

        pod_count++;
        return pf;
    }

    return NULL;
}

/* ---------------- UPDATE FEATURE ---------------- */

void update_feature(const char *pod, const char *feature, int value) {
    struct pod_feature *pf = get_pod_feature(pod);
    if (!pf)
        return;

    if (strcmp(feature, "file_access") == 0) {
        pf->file_access += value;

    } else if (strcmp(feature, "net") == 0) {
        pf->net += value;

    } else if (strcmp(feature, "exec") == 0) {
        pf->exec += value;

    } else if (strcmp(feature, "sensitive_file") == 0) {
        pf->sensitive_file += value;

    } else {
        printf("[WARN] unknown feature: %s\n", feature);
    }
}

/* ---------------- APPLY FILE RULES ---------------- */

void apply_file_rules(const char *pod, const char *filename, int type, const char *comm) {
    for (int i = 0; i < rule_count; i++) {
        struct feature_rule *r = &rules[i];

        if (strcmp(r->event_type, "file") != 0)
            continue;

        if (strcmp(r->field, "any") == 0) {
            update_feature(pod, r->feature, r->weight);
            continue;
        }

        if (strcmp(r->field, "filename") == 0) {
            if (filename && strstr(filename, r->value)) {
                update_feature(pod, r->feature, r->weight);
            }
        }

        if (strcmp(r->field, "type") == 0) {
            if (type == 1 && strcmp(r->value, "exec") == 0) {
                update_feature(pod, r->feature, r->weight);
            }
        }

	if (strcmp(r->field, "comm") == 0) {
	   if (comm && strstr(comm, r->value)) {
	       update_feature(pod, r->feature, r->weight);
	   }
	}

    }
}
/* ---------------- APPLY NETWORK RULES ---------------- */

void apply_network_rules(const char *pod) {
    for (int i = 0; i < rule_count; i++) {
        struct feature_rule *r = &rules[i];

        if (strcmp(r->event_type, "network") == 0) {
            update_feature(pod, r->feature, r->weight);
        }
    }
}

/* ---------------- LOAD RULES ---------------- */

void load_feature_rules(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("feature_rules.conf");
        return;
    }

    char line[256];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || strlen(line) < 5)
            continue;

        line[strcspn(line, "\n")] = 0;

        char event[16], field[32], value[64], feature[64];
        int weight;

        if (sscanf(line,
                   "%15[^|]|%31[^|]|%63[^|]|%63[^|]|%d",
                   event, field, value, feature, &weight) != 5) {
            printf("[feature_engine] invalid rule: %s\n", line);
            continue;
        }

        trim(event);
        trim(field);
        trim(value);
        trim(feature);

        if (rule_count >= MAX_RULES)
            break;

        struct feature_rule *r = &rules[rule_count];

	safe_copy(r->event_type, event, sizeof(r->event_type));
	safe_copy(r->field, field, sizeof(r->field));
	safe_copy(r->value, value, sizeof(r->value));
	safe_copy(r->feature, feature, sizeof(r->feature));

	r->weight = weight;

        //printf("[feature_engine] rule loaded: event=%s field=%s value=%s feature=%s weight=%d\n",
        //       r->event_type, r->field, r->value, r->feature, r->weight);

        rule_count++;
    }

    fclose(f);

    printf("[feature_engine] total rules: %d\n", rule_count);
}

/* ---------------- FLUSH FEATURES ---------------- */

void flush_features() {
    FILE *f = fopen("ai-engine/ml/features.log", "a");
    if (!f) {
        perror("features.log");
        return;
    }

    for (int i = 0; i < pod_count; i++) {
        struct pod_feature *pf = &pod_stats[i];

        fprintf(f,
            "{\"pod\":\"%s\",\"file_access\":%d,\"net\":%d,\"exec\":%d,\"sensitive_file\":%d}\n",
            pf->pod,
            pf->file_access,
            pf->net,
            pf->exec,
            pf->sensitive_file
        );

        /* reset */
        pf->file_access = 0;
        pf->net = 0;
        pf->exec = 0;
        pf->sensitive_file = 0;
    }

    fclose(f);
}
