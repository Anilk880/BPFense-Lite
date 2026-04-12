#ifndef DECISION_ENGINE_H
#define DECISION_ENGINE_H

#include "event.h"

/* NEW STRUCT for AI decision */
typedef struct {
    int pid;
    float score;
    char pod[64];
    char namespace[64];
    char comm[32];
    char file[128];
} ai_event_t;

typedef enum {
    NORMAL,
    MEDIUM,
    HIGH
} severity_t;

severity_t decide(ai_event_t *e);
const char* severity_str(severity_t s);

#endif
