#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include "../include/event.h"
#include <stdbool.h>
#include <pthread.h>

#define MAX_RULES 32
#define MAX_MATCH 16

/* ---------------- RULE STRUCT ---------------- */

struct rule {
    char name[64];
    int enabled;
    char match[MAX_MATCH][128];
    int match_count;
};

/* ---------------- RULE ENGINE ---------------- */

struct rule_engine {
    struct rule rules[MAX_RULES];
    int rule_count;
    pthread_mutex_t lock;
};

/* ---------------- API ---------------- */

/* load rules from directory */
void load_rules_from_dir(struct rule_engine *engine, const char *dir);

/* evaluate event against rules */
bool evaluate_event(struct rule_engine *engine, struct event *e);

/* hot reload support */
void reload_rules(struct rule_engine *engine);
void watch_rules(struct rule_engine *engine);

#endif
