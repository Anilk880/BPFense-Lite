#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ai_engine.h"

/* ---------------- RULE MATCH ---------------- */

static int match_rule(const char *value, const char *target) {
    if (!value || !target) return 0;
    return strstr(value, target) != NULL;
}

/* ---------------- APPLY RULES ---------------- */

static void apply_ai_rules(const char *process, const char *file,
                          int *exec, int *sensitive) {

    FILE *fp = fopen("rules/test.rule", "r");
    if (!fp) return;

    char line[128];

    while (fgets(line, sizeof(line), fp)) {

        if (strncmp(line, "match=", 6) == 0) {
            char *val = strchr(line, '=') + 1;
            if (!val) continue;

            val[strcspn(val, "\n")] = 0;

            /* process-based match */
            if (match_rule(process, val)) {
                if (!strcmp(val, "bash") || !strcmp(val, "sh"))
                    *exec = 1;
            }

            /* file-based match */
            if (match_rule(file, val)) {
                if (!strcmp(val, "passwd") || !strcmp(val, "shadow"))
                    *sensitive = 1;
            }
        }
    }

    fclose(fp);
}

/* ---------------- INIT ---------------- */

void ai_init() {
    printf("[AI] Initialized (Lite Mode)\n");
}

/* ---------------- FILE ANALYSIS ---------------- */

int ai_analyze(const char *pod, const char *ns,
               const char *process, const char *file) {

    int exec = 0;
    int sensitive = 0;

    apply_ai_rules(process, file, &exec, &sensitive);

    if (sensitive || exec) {
        printf("[AI ALERT] pod=%s proc=%s file=%s\n",
               pod, process, file);
        return 1;
    }

    return 0;
}

/* ---------------- NETWORK ---------------- */

int ai_analyze_network(const char *pod, const char *ns,
                       const char *dst_ip, int port, int proto) {

    printf("[AI-NET] pod=%s -> %s:%d proto=%d\n",
           pod, dst_ip, port, proto);

    return 0;
}

/* ---------------- SCORE ---------------- */

float ai_get_score(const char *pod, const char *ns,
                   const char *process, const char *file,
                   int *rule_flag)
{
    int exec = 0;
    int sensitive = 0;

    apply_ai_rules(process, file, &exec, &sensitive);

    float score = 0.5;

    /* heuristic scoring */
    if (sensitive)
        score -= 0.3;

    if (exec)
        score -= 0.2;

    if (strstr(process, "curl"))
        score -= 0.05;

    if (strstr(process, "nc") || strstr(process, "netcat"))
        score -= 0.2;

    /* clamp */
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;

    if (rule_flag)
        *rule_flag = (sensitive || exec);

    return score;
}
