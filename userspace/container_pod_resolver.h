#ifndef CONTAINER_POD_RESOLVER_H
#define CONTAINER_POD_RESOLVER_H

#include <stdint.h>
#include <stddef.h>

void resolver_refresh();
void resolve_by_cgroup(uint64_t cgid, char *pod, size_t pod_sz,
                       char *ns, size_t ns_sz);

#endif
