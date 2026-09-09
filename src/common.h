#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

struct datarec {
  __u64 rx_packets;
  __u64 rx_bytes;
};

#define aethon_always_inline __always_inline

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX 5
#endif

#endif
