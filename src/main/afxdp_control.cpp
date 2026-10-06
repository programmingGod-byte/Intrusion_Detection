#include "../af_xdp_header.h"
#include "aethon/aethon.h"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <sched.h>
#include <pthread.h>
#include <poll.h>
#include "udp_assembler.cpp"
#include "ip_address.cpp"

/*
  For IPv4 UDP
  [ Ethernet Header (14B) ][ IPv4 Header (20B) ][ Payload / UDP Header ]
^                        ^                    ^
|                        |                    |
pkt                      pkt + 14             pkt + 14 + iph->ihl*4

*/
namespace aethon {
namespace xdp {

// Global packet and byte counters, aligned on separate 64-byte CPU cachelines
struct alignas(implementation::hardware_destructive_interference_size) CaptureStats {
  alignas(implementation::hardware_destructive_interference_size) std::atomic<uint64_t> total_packets{0};
  alignas(implementation::hardware_destructive_interference_size) std::atomic<uint64_t> total_bytes{0};
};

inline CaptureStats g_stats;

inline std::atomic<bool> g_running{true};

static inline void set_cpu_affinity(int core_id) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

// Templated worker that accepts any AFXDPEngine configuration
template <typename Engine>
void rx_worker(Engine &engine, int queue_id) {
  using Config = typename Engine::config_type;

  // Pin this worker thread to its dedicated CPU core (skip Core 0 for OS)
  int core_count = std::thread::hardware_concurrency();
  int available_worker_cores = core_count > 1 ? core_count - 1 : 1;
  int target_core = (queue_id % available_worker_cores) + 1; // +1 to skip Core 0
  
  if (core_count == 1) {
      target_core = 0; // Fallback for single-core machines
  }
  
  set_cpu_affinity(target_core);

  auto *sock = engine.get_socket(queue_id);
  if (!sock) {
    std::cerr << "[Queue " << queue_id << "] Error: Invalid socket pointer!\n";
    return;
  }

  int sock_fd = xsk_socket__fd(sock->xsk);
  std::cout << "[Queue " << queue_id << "] Worker started on Core " << target_core << "\n";

  // Tell Linux to monitor our AF_XDP socket
  struct pollfd fds[1];
  fds[0].fd = sock_fd;
  fds[0].events = POLLIN;

  // Ultra-fast stack-allocated ring buffer with capacity defined by template Config
  FallbackRing<Config::FALLBACK_CAPACITY> fallback_ring;

  // Per-worker-thread UDP assembler engine (dedicated Core-pinned instance)
  UDPIpv4Assembler::UDPassemblerEngine assembler;

  while (g_running.load(std::memory_order_relaxed)) {
    uint32_t idx_rx = 0;
    unsigned int rcvd = xsk_ring_cons__peek(&sock->rx, Config::BATCH_SIZE, &idx_rx);
    
    if (AETHON_UNLIKELY(!rcvd)) {
        // If we have pending fallback buffers, try to flush them to the Fill Ring now
        if (!fallback_ring.empty()) {
            uint32_t idx_fq = 0;
            size_t count = fallback_ring.size();
            size_t available = xsk_ring_prod__reserve(&sock->umen->fq, count, &idx_fq);
            if (AETHON_LIKELY(available > 0)) {
                for (size_t i = 0; i < available; ++i) {
                    *xsk_ring_prod__fill_addr(&sock->umen->fq, idx_fq + i) = fallback_ring.get(i);
                }
                xsk_ring_prod__submit(&sock->umen->fq, available);
                fallback_ring.advance(available);
            }
        }

        // Put thread to sleep waiting for new packets or fill ring wake-up (reduces idle CPU to ~0%)
        poll(fds, 1, 50);
        continue;
    }

    uint64_t batch_bytes = 0;
    for (unsigned int i = 0; i < rcvd; ++i) {
      // Software prefetch the next descriptor ahead into CPU L1 cache
      if (i + 4 < rcvd) {
        AETHON_BUILTIN_PREFETCH(xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i + 4), 0, 1);
      }
      const auto *__restrict__ desc = xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i);

      /* PACKET PROCESSING LOGIC */
      const uint8_t *__restrict__ pkt = reinterpret_cast<const uint8_t *>(
          xsk_umem__get_data(sock->umen->buffer, desc->addr));
      const auto *__restrict__ eth = reinterpret_cast<const struct ether_header *>(pkt);

      if (AETHON_LIKELY(ntohs(eth->ether_type) == ETHERTYPE_IP)) {
        if (AETHON_LIKELY(desc->len >= sizeof(struct ether_header) + sizeof(struct iphdr))) {
          const auto *__restrict__ iph = reinterpret_cast<const struct iphdr *>(pkt + sizeof(struct ether_header));

          // Host IP filter: Accept traffic for our interface private IPs, broadcast, or multicast
          const uint32_t dst_ip = iph->daddr;
          const bool is_for_this_host = g_host_ips.contains(dst_ip) ||
                                        (dst_ip == INADDR_BROADCAST) ||
                                        (IN_MULTICAST(ntohl(dst_ip)));

          if (AETHON_LIKELY(is_for_this_host && iph->protocol == IPPROTO_UDP)) {
            uint16_t frag_field = ntohs(iph->frag_off);
            bool more_fragments = (frag_field & IP_MF) != 0;
            uint16_t frag_offset = (frag_field & IP_OFFMASK) * 8;
            
            size_t ip_hdr_len = iph->ihl * 4;
            const uint8_t *__restrict__ frag_payload = reinterpret_cast<const uint8_t *>(iph) + ip_hdr_len;
            uint16_t frag_len = ntohs(iph->tot_len) - ip_hdr_len;

            // 99.5% of packets are unfragmented (expect 1 with 0.995 probability)
            if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY((!more_fragments && frag_offset == 0), 1, 0.995)) {
              if (AETHON_LIKELY(frag_len >= sizeof(struct udphdr))) {
                const auto *__restrict__ udph = reinterpret_cast<const struct udphdr *>(frag_payload);
                const uint8_t *__restrict__ udp_app_payload = frag_payload + sizeof(struct udphdr);
                size_t udp_app_len = frag_len - sizeof(struct udphdr);

                // Fast Path: Payload available for Hyperscan scanning
                (void)udph;
                (void)udp_app_payload;
                (void)udp_app_len;
              }
            } else {
              // Fragmented Packet Path
              UDPIpv4Assembler::FragmentKey key;
              key.src_ip   = iph->saddr;
              key.dst_ip   = iph->daddr;
              key.ip_id    = ntohs(iph->id);
              key.protocol = iph->protocol;

              uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                  std::chrono::steady_clock::now().time_since_epoch()).count();

              UDPIpv4Assembler::AssemblyResult res = assembler.process_fragment(
                  key, frag_offset, frag_payload, frag_len, more_fragments, now_ns);

              if (AETHON_UNLIKELY(res.is_complete)) {
                // Reassembled Datagram: Full payload available for Hyperscan scanning
                (void)res;

                assembler.release_completed(res);
              }
            }
          }
        }
      }

      batch_bytes += desc->len;
      fallback_ring.push(desc->addr);
    }

    // Update atomic counters (relaxed ordering for low contention)
    g_stats.total_packets.fetch_add(rcvd, std::memory_order_relaxed);
    g_stats.total_bytes.fetch_add(batch_bytes, std::memory_order_relaxed);

    // Release the consumed descriptors in the RX ring
    xsk_ring_cons__release(&sock->rx, rcvd);

    // Refill the Fill Ring with our recycled buffer addresses
    if (!fallback_ring.empty()) {
      uint32_t idx_fq = 0;
      size_t count = fallback_ring.size();
      size_t available = xsk_ring_prod__reserve(&sock->umen->fq, count, &idx_fq);
      if (AETHON_LIKELY(available > 0)) {
        for (size_t i = 0; i < available; ++i) {
          *xsk_ring_prod__fill_addr(&sock->umen->fq, idx_fq + i) = fallback_ring.get(i);
        }
        xsk_ring_prod__submit(&sock->umen->fq, available);
        fallback_ring.advance(available);
      }
    }
  }
}

inline void stats_printer() {
  // Pin telemetry thread strictly to Core 0 (alongside Linux OS & IRQs)
  // so packet workers on Cores 1+ have 100% uninterrupted CPU time
  set_cpu_affinity(0);

  uint64_t last_packets = 0;
  uint64_t last_bytes = 0;

  while (g_running.load(std::memory_order_relaxed)) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    uint64_t current_packets = g_stats.total_packets.load(std::memory_order_relaxed);
    uint64_t current_bytes = g_stats.total_bytes.load(std::memory_order_relaxed);

    uint64_t pps = current_packets - last_packets;
    uint64_t bps = current_bytes - last_bytes;

    double mbps = (bps * 8.0) / 1000000.0; // Megabits per second

    std::cout << "\r[Stats] Speed: " << pps << " pps | " 
              << std::fixed << std::setprecision(2) << mbps << " Mbps" << std::flush;

    last_packets = current_packets;
    last_bytes = current_bytes;
  }
}

// ============================================================================
// PARAMETER CONFIGURATION
// ============================================================================
// DefaultEngine uses XdpConfig with 4096 frames (8MB UMEM), 2048 ring sizes, 64 batch.
// You can define custom configs here if needed.
using ActiveEngine = DefaultEngine;

static void sig_handler(int) {
  g_running.store(false, std::memory_order_relaxed);
}

} // namespace xdp
} // namespace aethon

#include <csignal>

int main(int argc, char **argv) {
  using namespace aethon::xdp;

  std::signal(SIGINT, sig_handler);
  std::signal(SIGTERM, sig_handler);

  const char *ifname = (argc > 1) ? argv[1] : "veth0";
  const char *prog_path = (argc > 2) ? argv[2] : "src/main/xdp_kern_prog.o";

  // Discover and cache all local IPv4 addresses on this interface (AWS private IPs)
  aethon::load_interface_ips(ifname);

  std::cout << "Starting AF_XDP on interface: " << ifname << "\n";
  std::cout << "Using eBPF Program: " << prog_path << "\n";

  ActiveEngine engine;
  if (!engine.setup(ifname, prog_path, "aethon_xdp_prog_main",
                    XDP_MODE_SKB, "aethon_xsks_map", "queue_config_map")) {
    std::cerr << "Failed to initialize AF_XDP engine.\n";
    return 1;
  }

  int num_queues = engine.active_queues();
  std::cout << "Running on " << num_queues << " queues...\n";

  // Spawn 1 thread per queue
  std::vector<std::thread> workers;
  
  // Start the statistics printer thread
  workers.emplace_back(stats_printer);

  for (int q = 0; q < num_queues; ++q) {
    workers.emplace_back(rx_worker<ActiveEngine>, std::ref(engine), q);
  }

  for (auto &w : workers) {
    w.join();
  }

  std::cout << "\n[Engine] Gracefully stopped all workers.\n";
  return 0;
}
