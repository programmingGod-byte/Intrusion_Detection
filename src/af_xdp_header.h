#pragma once

#include "aethon/aethon.h"
#include "common.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <optional>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <array>

#define AETHON_NUM_FRAMES 4096
#define AETHON_FRAME_SIZE 2048 // size of individual
#define AETHON_UMEM_SIZE (AETHON_NUM_FRAMES * AETHON_FRAME_SIZE)
#define AETHON_RX_RING_SIZE XSK_RING_CONS__DEFAULT_NUM_DESCS
#define AETHON_TX_RING XSK_RING_PROD__DEFAULT_NUM_DESCS
#define AETHON_XDP_RUNNING_MODE XDP_FLAGS_SKB_MODE
#define AETHON_MAX_NIC_QUEUES 64

namespace aethon {
namespace xdp {

struct aethon_umen_info {
  struct xsk_ring_prod fq; // fill ring
  struct xsk_ring_cons cq; // consumer ring

  struct xsk_umem *umen;
  void *buffer;
};

// 64-byte aligned to prevent False Sharing / Cache Bouncing across CPU cores
struct alignas(implementation::hardware_destructive_interference_size) aethon_xsk_socket_info {
  struct xsk_ring_cons rx; // kernal to af_xdp
  struct xsk_ring_prod tx;  // af_xdp to kernal

  struct xsk_socket *xsk;
  struct aethon_umen_info *umen;
};

// Each queue slot occupies its own dedicated 64-byte cache line
struct alignas(implementation::hardware_constructive_interference_size) QueueSlot {
  aethon_xsk_socket_info *socket_info{nullptr};
};

inline aethon_xsk_socket_info *xsk_info = nullptr;
inline std::array<QueueSlot, AETHON_MAX_NIC_QUEUES> xsk_sockets{};
inline int total_active_queues = 0;

// get the no of queue from the NIC hardware
inline int get_nic_queue_count(const char *ifname){
  struct ethtool_channels channels {};
  channels.cmd = ETHTOOL_GCHANNELS;
  struct ifreq ifr{};

  std::strncpy(ifr.ifr_name,ifname,IFNAMSIZ -1);
   ifr.ifr_data = reinterpret_cast<char *>(&channels);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 1; // Fallback to 1 queue if socket fails
    }
    int ret = ioctl(fd, SIOCETHTOOL, &ifr);
    close(fd);
    if (ret == 0) {
        // 'combined_count' is for NICs with combined RX/TX queues
        if (channels.combined_count > 0) {
            return channels.combined_count;
        }
        // Otherwise check dedicated 'rx_count'
        if (channels.rx_count > 0) {
            return channels.rx_count;
        }
    }
    return 1;
}

}; // namespace xdp

} // namespace aethon
// UMEN AND AF XDP

inline std::optional<aethon::xdp::aethon_umen_info *> configure_umen(void) {
  struct aethon::xdp::aethon_umen_info *umen;
  void *bufs;
  int ret;

  umen = (struct aethon::xdp::aethon_umen_info *)calloc(1, sizeof(*umen));
  if (!umen) {
    return std::nullopt;
  }

  ret = posix_memalign(&bufs, getpagesize(), AETHON_UMEM_SIZE);
  if (ret) {
    free(umen);
    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "Cannot able to allocate memory for umen");
    return std::nullopt;
  }

  int code = xsk_umem__create(&umen->umen, bufs, AETHON_UMEM_SIZE, &umen->fq,
                              &umen->cq, NULL);
  if (code) {
    free(bufs);
    free(umen);

    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "cannot map UMEN memory to the xsk_umen_create");
    return std::nullopt;
  }

  umen->buffer = bufs;
  return umen;
}

inline bool raise_memory_locking() {
  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
    return false;
  }
  return true;
}

inline void setup_af_xdp_for_all_queue(const char *ifname, const char *prog_name,
                                       const char *prog_section_name,
                                       enum xdp_attach_mode xpd_running_mode,
                                       const char *xdp_xsk_map_name) {
  int num_queues = aethon::xdp::get_nic_queue_count(ifname);
  if (num_queues > AETHON_MAX_NIC_QUEUES) {
    num_queues = AETHON_MAX_NIC_QUEUES;
  }
  aethon::xdp::total_active_queues = num_queues;

  unsigned int ifindex = if_nametoindex(ifname);
  if (ifindex == 0) {
    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "cannot able to find the interface ", ifname);
  }

  if (!raise_memory_locking()) {
    AETHON_SAFE_CHECK(Trait::always_false<int>, "cannot able to lokc pages ");
  }

  // 1. Load eBPF Object ONCE for the interface
  struct bpf_object *obj = bpf_object__open_file(prog_name, NULL);
  if (!obj || bpf_object__load(obj)) {
    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "cannot open or load the program ", prog_name);
  }

  // "aethon_xdp_prog_main" is the name of our C function in xdp_kern_prog.c
  struct bpf_program *bpf_prog = bpf_object__find_program_by_name(obj, "aethon_xdp_prog_main");
  if (!bpf_prog) {
    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "cannot find program 'aethon_xdp_prog_main' in ", prog_name);
  }

  int prog_fd = bpf_program__fd(bpf_prog);
  
  // Attach the eBPF program to the interface
  int err = bpf_xdp_attach(ifindex, prog_fd, xpd_running_mode, NULL);
  if (err < 0) {
    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "cannot attach the program to the interface ", ifname);
  }

  // Find the XSK map which is used to redirect packets to our sockets
  struct bpf_map *map = bpf_object__find_map_by_name(obj, xdp_xsk_map_name);
  if (!map) {
    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "cannot able to find the map: ", xdp_xsk_map_name);
    return;
  }

  int xsk_map_fd = bpf_map__fd(map);
  if (xsk_map_fd < 0) {
    AETHON_SAFE_CHECK(Trait::always_false<int>,
                      "cannot able to get map fd: ", xdp_xsk_map_name);
    return;
  }

  // 2. Setup AF_XDP sockets for EACH queue and add them to the shared map
  for (int q = 0; q < num_queues; ++q) {
    std::optional<aethon::xdp::aethon_umen_info *> umen_info = configure_umen();
    if (!umen_info) {
      AETHON_SAFE_CHECK(Trait::always_false<int>,
                        "cannot able to run the aethon_umen_info for queue");
    }

    aethon::xdp::aethon_xsk_socket_info *sock_info = (aethon::xdp::aethon_xsk_socket_info *)calloc(
        1, sizeof(*sock_info));

    struct xsk_socket_config xsk_config {
      .rx_size = AETHON_RX_RING_SIZE, .tx_size = AETHON_TX_RING,
      .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
      .xdp_flags = AETHON_XDP_RUNNING_MODE, .bind_flags = XDP_COPY
    };

    err = xsk_socket__create(&sock_info->xsk, ifname, q,
                             umen_info.value()->umen, &sock_info->rx,
                             &sock_info->tx, &xsk_config);

    if (err) {
      AETHON_SAFE_CHECK(Trait::always_false<int>,
                        "cannot attach the config to the xsk_socket");
    }

    sock_info->umen = umen_info.value();

    // Register the socket in the BPF XSK map
    int xsk_fd = xsk_socket__fd(sock_info->xsk);
    int map_update_err = bpf_map_update_elem(xsk_map_fd, &q, &xsk_fd, 0);
    if (map_update_err < 0) {
      AETHON_SAFE_CHECK(Trait::always_false<int>,
                        "cannot update BPF xsk map with socket fd");
    }

    // Populate Fill Ring with initial UMEM frames
    uint32_t idx = 0;
    uint32_t reserve_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    int fq_res = xsk_ring_prod__reserve(&umen_info.value()->fq, reserve_size, &idx);
    if (fq_res == reserve_size) {
      for (uint32_t i = 0; i < reserve_size; ++i) {
        *xsk_ring_prod__fill_addr(&umen_info.value()->fq, idx++) = i * AETHON_FRAME_SIZE;
      }
      xsk_ring_prod__submit(&umen_info.value()->fq, reserve_size);
    } else {
      fprintf(stderr, "WARNING: Failed to reserve %u slots in Fill Ring (got %d) on queue %d\n", reserve_size, fq_res, q);
    }
    
    aethon::xdp::xsk_sockets[q].socket_info = sock_info;
  }
}

