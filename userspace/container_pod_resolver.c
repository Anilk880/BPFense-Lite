#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_ENTRIES 1024
#define CGROUP_PATH_LEN 256

struct pod_entry {
    uint64_t cgroup_id;
    char pod[128];
    char ns[64];
};

static struct pod_entry pod_map[MAX_ENTRIES];
static int pod_count = 0;

/* ----------------------------------------
   Get cgroup_id from path
----------------------------------------- */
static uint64_t get_cgroup_id_from_path(const char *path)
{
    FILE *f;
    char cmd[512];
    uint64_t id = 0;

    if (snprintf(cmd, sizeof(cmd),
                 "stat -c %%i %s 2>/dev/null", path) >= sizeof(cmd)) {
        return 0;
    }

    f = popen(cmd, "r");
    if (!f)
        return 0;

    if (fscanf(f, "%lu", &id) != 1) {
        id = 0;
    }

    pclose(f);
    return id;
}

/* ---------------------------------------- */
static void clear_cache()
{
    pod_count = 0;
    memset(pod_map, 0, sizeof(pod_map));
}

/* ---------------------------------------- */
static void add_entry(uint64_t cgid, const char *pod, const char *ns)
{
    if (pod_count >= MAX_ENTRIES)
        return;

    pod_map[pod_count].cgroup_id = cgid;

    snprintf(pod_map[pod_count].pod,
             sizeof(pod_map[pod_count].pod), "%s", pod);

    snprintf(pod_map[pod_count].ns,
             sizeof(pod_map[pod_count].ns), "%s", ns);

    pod_count++;
}

/* ----------------------------------------
   Refresh mapping (k3s compatible)
----------------------------------------- */
void resolver_refresh()
{
    FILE *fp;
    char line[512];

    clear_cache();

    fp = popen("crictl ps -q", "r");
    if (!fp) {
        perror("crictl ps failed");
        return;
    }

    while (fgets(line, sizeof(line), fp)) {

        char container_id[128];
        char cmd[512];

        line[strcspn(line, "\n")] = 0;

        if (strlen(line) == 0 || strlen(line) >= sizeof(container_id))
            continue;

        snprintf(container_id, sizeof(container_id), "%s", line);

        /* -------- get pod + namespace -------- */

        if (snprintf(cmd, sizeof(cmd),
                     "crictl inspect %s 2>/dev/null", container_id) >= sizeof(cmd)) {
            continue;
        }

        FILE *inspect_fp = popen(cmd, "r");
        if (!inspect_fp)
            continue;

        char pod[128] = "unknown";
        char ns[64] = "unknown";
        char inspect_line[512];

        while (fgets(inspect_line, sizeof(inspect_line), inspect_fp)) {

            if (strstr(inspect_line, "\"name\":") &&
                strstr(inspect_line, "container") == NULL) {

                char *p = strchr(inspect_line, ':');
                if (!p) continue;

                p++;
                while (*p == ' ' || *p == '"') p++;

                char *end = strchr(p, '"');
                if (!end) continue;

                snprintf(pod, sizeof(pod), "%.*s", (int)(end - p), p);
            }

            if (strstr(inspect_line, "io.kubernetes.pod.namespace")) {

                char *p = strchr(inspect_line, ':');
                if (!p) continue;

                p++;
                while (*p == ' ' || *p == '"') p++;

                char *end = strchr(p, '"');
                if (!end) continue;

                snprintf(ns, sizeof(ns), "%.*s", (int)(end - p), p);
            }
        }

        pclose(inspect_fp);

        /* -------- REAL FIX: scan cgroup -------- */

        char find_cmd[512];

        snprintf(find_cmd, sizeof(find_cmd),
                 "find /sys/fs/cgroup -name '*%s*' 2>/dev/null",
                 container_id);

        FILE *find_fp = popen(find_cmd, "r");
        if (!find_fp)
            continue;

        char path[512];

        while (fgets(path, sizeof(path), find_fp)) {

            path[strcspn(path, "\n")] = 0;

            /* only consider .scope */
            if (!strstr(path, ".scope"))
                continue;

            uint64_t cgid = get_cgroup_id_from_path(path);

            if (cgid != 0) {
                add_entry(cgid, pod, ns);
                break;
            }
        }

        pclose(find_fp);
    }

    pclose(fp);

    printf("[resolver] loaded %d pod mappings\n", pod_count);
}
/* ----------------------------------------
   Lookup
----------------------------------------- */
void resolve_by_cgroup(uint64_t cgid,
                       char *pod, size_t pod_sz,
                       char *ns, size_t ns_sz)
{
    for (int i = 0; i < pod_count; i++) {
        if (pod_map[i].cgroup_id == cgid) {
            snprintf(pod, pod_sz, "%s", pod_map[i].pod);
            snprintf(ns, ns_sz, "%s", pod_map[i].ns);
            return;
        }
    }

    snprintf(pod, pod_sz, "host");
    snprintf(ns, ns_sz, "host");
}
