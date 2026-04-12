#ifndef AGENT_ENGINE_H
#define AGENT_ENGINE_H

#include <time.h>
#include "decision_engine.h"

#define MAX_PODS 128
#define TIME_WINDOW 30   // seconds

typedef struct {
    char pod[64];
    int anomaly_count;
    int escalated;
    time_t last_seen;
} pod_state_t;

/* Agent logic */
severity_t agent_process(ai_event_t *e, severity_t current);

#endif
