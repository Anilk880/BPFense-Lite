#include <stdio.h>
#include <stdlib.h>
#include "response_engine.h"

void respond(ai_event_t *e, severity_t s) {

    switch (s) {

        case HIGH:
            printf("[ACTION] KILL_POD pod=%s\n", e->pod);
            // system("kubectl delete pod ..."); // keep disabled for now
            break;

        case MEDIUM:
            printf("[ACTION] ALERT pod=%s\n", e->pod);
            break;

        case NORMAL:
        default:
            break;
    }
}
