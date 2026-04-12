#include "decision_engine.h"

severity_t decide(ai_event_t *e) {

    if (e->score < 0.15)
        return HIGH;

    if (e->score < 0.25)
        return MEDIUM;

    return NORMAL;
}

const char* severity_str(severity_t s) {
    switch (s) {
        case HIGH: return "HIGH";
        case MEDIUM: return "MEDIUM";
        default: return "NORMAL";
    }
}
