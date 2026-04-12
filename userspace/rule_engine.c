#include "rule_engine.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#define MAX_RULES 32
#define MAX_MATCH 16

#define EVENT_BUF_LEN 4096

void reload_rules(struct rule_engine *engine)
{
    struct rule_engine new_engine = {0};

    load_rules_from_dir(&new_engine, "./rules");

    pthread_mutex_lock(&engine->lock);

    engine->rule_count = new_engine.rule_count;
    memcpy(engine->rules, new_engine.rules, sizeof(new_engine.rules));

    pthread_mutex_unlock(&engine->lock);

    printf("[rule_engine] reloaded %d rules\n", engine->rule_count);
}

void watch_rules(struct rule_engine *engine)
{
    int fd, wd;
    char buffer[EVENT_BUF_LEN];

    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        return;
    }

    wd = inotify_add_watch(fd, "./rules",
                           IN_MODIFY | IN_CREATE | IN_DELETE);

    if (wd < 0) {
        perror("inotify_add_watch");
        close(fd);
        return;
    }

    printf("[rule_engine] watching ./rules for changes...\n");

    while (1) {
        int length = read(fd, buffer, EVENT_BUF_LEN);

        if (length <= 0)
            continue;

        /* Any change triggers reload */
        printf("[rule_engine] change detected → reloading rules...\n");

        reload_rules(engine);
    }

    close(fd);
}

/* parse single rule file */
static void parse_rule_file(struct rule_engine *engine, const char *path)
{
  FILE *f = fopen(path, "r");
  if (!f)
    return;

  struct rule r = {0};
  char line[256];

  while (fgets(line, sizeof(line), f)) {

    if (strncmp(line, "rule=", 5) == 0) {
      sscanf(line + 5, "%63s", r.name);
    }

    else if (strncmp(line, "enabled=", 8) == 0) {
      r.enabled = atoi(line + 8);
    }

    else if (strncmp(line, "match=", 6) == 0) {

      if (r.match_count < MAX_MATCH) {
        sscanf(line + 6, "%127s", r.match[r.match_count]);
        r.match_count++;
      }
    }
  }

  fclose(f);

  if (engine->rule_count < MAX_RULES) {
    engine->rules[engine->rule_count++] = r;
  }
}

/* load all rules from rules directory */
void load_rules_from_dir(struct rule_engine *engine, const char *dir)
{
  DIR *d;
  struct dirent *ent;

  engine->rule_count = 0;  // reset before loading

  d = opendir(dir);
  if (!d) {
    printf("[rule_engine] failed to open %s\n", dir);
    return;
  }

  while ((ent = readdir(d)) != NULL) {

    if (strstr(ent->d_name, ".rule")) {

      char path[512];
      snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

      parse_rule_file(engine, path);
    }
  }

  closedir(d);

  printf("[rule_engine] loaded %d rules\n", engine->rule_count);
}

/* event matching */
bool evaluate_event(struct rule_engine *engine, struct event *e)
{
  pthread_mutex_lock(&engine->lock);

  for (int i = 0; i < engine->rule_count; i++) {

    struct rule *r = &engine->rules[i];

    if (!r->enabled)
      continue;

    for (int j = 0; j < r->match_count; j++) {

      if (strstr(e->filename, r->match[j]) ||
          strstr(e->comm, r->match[j])) {

        pthread_mutex_unlock(&engine->lock);
        return true;
      }
    }
  }

  pthread_mutex_unlock(&engine->lock);
  return false;
}
