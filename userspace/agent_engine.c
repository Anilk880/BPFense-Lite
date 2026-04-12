#include <stdio.h>
#include <string.h>
#include <time.h>

#include "agent_engine.h"

/* ---------------- STORAGE ---------------- */

static pod_state_t pod_states[MAX_PODS];
static int pod_count = 0;

/* ---------------- GET OR CREATE ---------------- */

static pod_state_t* get_pod_state(const char *pod) {

    for (int i = 0; i < pod_count; i++) {
        if (strcmp(pod_states[i].pod, pod) == 0)
            return &pod_states[i];
    }

    if (pod_count < MAX_PODS) {
        pod_state_t *ps = &pod_states[pod_count];

        strncpy(ps->pod, pod, sizeof(ps->pod) - 1);
        ps->pod[sizeof(ps->pod) - 1] = '\0';

        ps->anomaly_count = 0;
	ps->escalated = 0;
        ps->last_seen = time(NULL);

        pod_count++;
        return ps;
    }

    return NULL;
}

/* ---------------- AGENT LOGIC ---------------- */

severity_t agent_process(ai_event_t *e, severity_t current) {

    pod_state_t *ps = get_pod_state(e->pod);
    if (!ps)
        return current;

    time_t now = time(NULL);

    /* Reset if outside time window */
    if (now - ps->last_seen > TIME_WINDOW) {
        ps->anomaly_count = 0;
	ps->escalated = 0;
    }

    ps->last_seen = now;

    /* Count anomalies */
    if (current == MEDIUM || current == HIGH) {
        ps->anomaly_count++;
    }

    /* Escalation logic */
    if (ps->anomaly_count >= 3 && ps->escalated == 0) {
	    printf("[AGENT] Escalation triggered for pod=%s count=%d\n",
			    e->pod, ps->anomaly_count);

	    ps->escalated = 1; 
	    return HIGH;
    }

    return current;
}
