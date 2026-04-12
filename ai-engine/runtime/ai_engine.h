#ifndef AI_ENGINE_H
#define AI_ENGINE_H

void ai_init();

/*
 * Analyze runtime (LSM) event
 * Example: file access, exec, etc.
 */
int ai_analyze(const char *pod, const char *ns, const char *process,
               const char *file);

/*
 * Analyze network event
 * Example: pod → external IP connection
 */
int ai_analyze_network(const char *pod, const char *ns, const char *dst_ip,
                       int port, int proto);

float ai_get_score(const char *pod,
                   const char *ns,
                   const char *process,
                   const char *file,
                   int *rule_flag);

#endif /* AI_ENGINE_H */
