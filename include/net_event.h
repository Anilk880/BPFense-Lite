#ifndef NET_EVENT_H
#define NET_EVENT_H

#include <stdint.h>

struct net_event {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
};

#endif
