#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "lsm_sensor.skel.h"
#include "network_sensor.skel.h"

#include "../ai-engine/runtime/ai_engine.h"
#include "container_pod_resolver.h"
#include "event.h"
#include "net_event.h"
#include "rule_engine.h"
#include "feature_extractor.h"
#include "decision_engine.h"
#include "response_engine.h"
#include "agent_engine.h"
#include "model_verify.h"

#define MODEL_PATH "ai-engine/ml/model.pkl"
#define SIG_PATH   "ai-engine/ml/model.sig"
#define PUBKEY_PATH "ai-engine/ml/public.pem"

#define DEBUG_PRINT 0

/* ---------------- DEDUP ---------------- */

static uint32_t last_src = 0;
static uint32_t last_dst = 0;
static uint16_t last_sport = 0;
static uint16_t last_dport = 0;
static uint8_t last_proto = 0;

static time_t last_ai_time = 0;
#define AI_INTERVAL 5 // AI RATE LIMIT in seconds

static volatile bool running = true;
static void sig_handler(int sig) { running = false; }

void *rule_watcher_thread(void *arg)
{
    struct rule_engine *engine = (struct rule_engine *)arg;
    watch_rules(engine);
    return NULL;
}

/* ---------------- POD RESOLUTION ---------------- */

static void resolve_pod_from_ip(const char *ip, char *pod, size_t pod_sz,
                                char *ns, size_t ns_sz) {
  FILE *fp;
  char cmd[256];
  char line[256];

  snprintf(cmd, sizeof(cmd), "kubectl get pods -A -o wide | grep %s", ip);

  fp = popen(cmd, "r");
  if (!fp)
    return;

  if (fgets(line, sizeof(line), fp)) {
    sscanf(line, "%63s %63s", ns, pod);
  }

  pclose(fp);
}

/* ---------------- NETWORK EVENTS ---------------- */

static int handle_network_event(void *ctx, void *data, size_t len) {
  struct net_event *e = data;
  struct in_addr s, d;

  char src_ip[32];
  char dst_ip[32];

  /* ---- dedup ---- */
  if (e->src_ip == last_src && e->dst_ip == last_dst &&
      e->src_port == last_sport && e->dst_port == last_dport &&
      e->protocol == last_proto)
    return 0;

  last_src = e->src_ip;
  last_dst = e->dst_ip;
  last_sport = e->src_port;
  last_dport = e->dst_port;
  last_proto = e->protocol;

  s.s_addr = e->src_ip;
  d.s_addr = e->dst_ip;

  strcpy(src_ip, inet_ntoa(s));
  strcpy(dst_ip, inet_ntoa(d));

  char pod[64] = "unknown";
  char ns[64] = "unknown";

  resolve_pod_from_ip(src_ip, pod, sizeof(pod), ns, sizeof(ns));

  /* ---------------- AI NETWORK ANALYSIS ---------------- */


    if (strcmp(pod, "unknown") == 0)
        return 0;

    if (strcmp(pod, "host") == 0)
        return 0;
    time_t now = time(NULL);


    /* ALWAYS update feature */
    apply_network_rules(pod);

    /* AI / logging rate-limited */
    if (now - last_ai_time >= AI_INTERVAL) {
      printf("[NETWORK] pod=%s ns=%s -> %s:%d proto=%d\n", pod, ns, dst_ip,
             e->dst_port, e->protocol);

      printf("[AI] analyzing network event...\n");

 //     ai_analyze_network(pod, ns, dst_ip, e->dst_port, e->protocol);

      last_ai_time = now;
    }

  return 0;
}

/* ---------------- LSM EVENTS ---------------- */

static int handle_event(void *ctx, void *data, size_t len) {
    struct rule_engine *engine = ctx;
    struct event *e = data;

    char pod[128] = "host";
    char ns[64] = "host";

    if (!strcmp(e->comm, "kubelet") || !strcmp(e->comm, "systemd") ||
        !strcmp(e->filename, "cgroup") || !strcmp(e->comm, "systemd-oomd") ||
        !strcmp(e->comm, "loader"))
        return 0;

    /* skip noisy system files */

    if (!strcmp(e->filename, "ld.so.cache") ||
       !strcmp(e->filename, "libc.so.6") ||
       !strcmp(e->filename, "ld-linux-x86-64.so.2"))
       return 0;

    if (strstr(e->comm, "containerd"))
        return 0;

    if (strstr(e->comm, "runc"))
       return 0;

    /* cgroup-based resolution */
    resolve_by_cgroup(e->cgroup_id, pod, sizeof(pod), ns, sizeof(ns));


    if (strcmp(pod, "host") == 0)
       return 0;

    if (strcmp(ns, "kube-system") == 0)
        return 0;

    /* ALWAYS update features */
    if (strlen(pod) > 0)
       apply_file_rules(pod, e->filename, e->type, e->comm);

    /* THEN evaluate rules */
    if (evaluate_event(engine, e)) {
    //    printf("[SUSPICIOUS] pid=%d pod=%s ns=%s comm=%s file=%s type=%d\n",
    //           e->pid, pod, ns, e->comm, e->filename, e->type);
    }


    /* ---------------- AI + DECISION ---------------- */

    int rule_flag = 0;

    float score = ai_get_score(pod, ns, e->comm, e->filename, &rule_flag);

    ai_event_t evt = {0};
    evt.pid = e->pid;
    evt.score = score;

    strcpy(evt.pod, pod);
    strcpy(evt.namespace, ns);
    strcpy(evt.comm, e->comm);
    strcpy(evt.file, e->filename);

    /* HYBRID DECISION */
    severity_t sev;

    if (rule_flag == 1)
	    sev = HIGH;
    else
	    sev = decide(&evt);

    /* Prevent instant kill on first event */
    if (sev == HIGH)
	    sev = MEDIUM;

    /* Agent logic  */
    sev = agent_process(&evt, sev);

    printf("[AI] pod=%s score=%.4f severity=%s rule=%d\n",
		    evt.pod, evt.score, severity_str(sev), rule_flag);

    respond(&evt, sev);
    return 0;
}

int main() {

  printf("[SECURITY] Verifying ML model signature...\n");

  if (!verify_model_signature(MODEL_PATH, SIG_PATH, PUBKEY_PATH)) {
      printf("[FATAL] Model signature INVALID. Blocking startup.\n");
      return 1;
  }

  printf("[SECURITY] Model signature VALID. Proceeding...\n");    

  struct ring_buffer *rb = NULL;
  struct ring_buffer *net_rb = NULL;

  struct lsm_sensor_bpf *skel;
  struct network_sensor_bpf *net_skel;

  struct bpf_link *xdp_link = NULL;

  struct rule_engine engine = {0};
  pthread_mutex_init(&engine.lock, NULL);

  load_rules_from_dir(&engine, "./rules");
  printf("[rule_engine] loaded %d rules\n", engine.rule_count);
  
  ai_init();

  resolver_refresh();

  pthread_t rule_thread;

  if (pthread_create(&rule_thread, NULL, rule_watcher_thread, &engine) != 0) {
      perror("pthread_create");
  } else {
    printf("[rule_engine] watcher thread started\n");
  }


  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* ---------------- LSM ---------------- */

  skel = lsm_sensor_bpf__open_and_load();
  if (!skel) {
    printf("Failed to load LSM BPF\n");
    return 1;
  }

  if (lsm_sensor_bpf__attach(skel)) {
    printf("Failed to attach LSM programs\n");
    return 1;
  }

  /* ---------------- NETWORK ---------------- */

  net_skel = network_sensor_bpf__open_and_load();
  if (!net_skel) {
    printf("Failed to load network sensor\n");
    return 1;
  }

  int ifindex = if_nametoindex("cni0");

  if (!ifindex) {
    printf("Failed to find interface cni0\n");
    return 1;
  }

  bpf_xdp_detach(ifindex, 0, NULL);

  xdp_link =
      bpf_program__attach_xdp(net_skel->progs.xdp_network_monitor, ifindex);

  if (!xdp_link) {
    printf("Failed to attach XDP program\n");
    return 1;
  }

 
  printf("[+] XDP network sensor attached to cni0\n");
  
  load_feature_rules("ai-engine/ml/feature_rules.conf");

  /* ---------------- RING BUFFER ---------------- */

  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &engine, NULL);

  net_rb = ring_buffer__new(bpf_map__fd(net_skel->maps.net_events),
                            handle_network_event, &engine, NULL);

  if (!rb || !net_rb) {
    printf("Failed to create ring buffers\n");
    return 1;
  }


  /* ---------------- LOOP ---------------- */


  time_t last_flush = time(NULL);

  while (running) {
	  ring_buffer__poll(net_rb, 100);
	  ring_buffer__poll(rb, 0);

	  time_t now = time(NULL);

	  if (now - last_flush >= 5) {
		  flush_features();
		  last_flush = now;
	  }
  }

  /* ---------------- CLEANUP ---------------- */

  printf("\nShutting down sensors...\n");
  pthread_cancel(rule_thread);
  pthread_join(rule_thread, NULL);

  pthread_mutex_destroy(&engine.lock);

  if (rb)
    ring_buffer__free(rb);

  if (net_rb)
    ring_buffer__free(net_rb);

  if (xdp_link)
    bpf_link__destroy(xdp_link);

  if (skel)
    lsm_sensor_bpf__destroy(skel);

  if (net_skel)
    network_sensor_bpf__destroy(net_skel);

  return 0;
}
