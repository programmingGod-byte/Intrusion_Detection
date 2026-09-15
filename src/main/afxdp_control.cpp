#include "../af_xdp_header.h"
#include <iostream>
#include <thread>
#include <vector>

#include <chrono>
#include <atomic>
#include <iomanip>

#include <sched.h>
#include <pthread.h>

// False sharing prevention: align counters on separate 64-byte CPU cachelines
alignas(64) std::atomic<uint64_t> total_packets{0};
alignas(64) std::atomic<uint64_t> total_bytes{0};

#include <poll.h>

// Zero-copy, stack-allocated, power-of-two circular fallback ring (0 malloc, 0 memmove)
template <size_t Capacity = 2048>
struct alignas(64) FallbackRing {
  static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
  static constexpr size_t MASK = Capacity - 1;

  uint64_t ring[Capacity];
  uint32_t head = 0;
  uint32_t tail = 0;

  AETHON_ALWAYS_INLINE bool empty() const noexcept { return head == tail; }
  AETHON_ALWAYS_INLINE size_t size() const noexcept { return head - tail; }

  AETHON_ALWAYS_INLINE void push(uint64_t addr) noexcept {
    ring[head++ & MASK] = addr;
  }

  AETHON_ALWAYS_INLINE uint64_t get(size_t offset = 0) const noexcept {
    return ring[(tail + offset) & MASK];
  }

  AETHON_ALWAYS_INLINE void advance(size_t count) noexcept {
    tail += count;
  }
};

static inline void set_cpu_affinity(int core_id) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

void rx_worker(int queue_id) {
  // Pin this worker thread to its dedicated CPU core for maximum L1/L2 cache locality
  set_cpu_affinity(queue_id % std::thread::hardware_concurrency());

  auto *sock = aethon::xdp::xsk_sockets[queue_id].socket_info;
  int sock_fd = xsk_socket__fd(sock->xsk);
  std::cout << "[Queue " << queue_id << "] Worker started on Core " 
            << (queue_id % std::thread::hardware_concurrency()) << "\n";

  // Tell Linux to monitor our AF_XDP socket
  struct pollfd fds[1];
  fds[0].fd = sock_fd;
  fds[0].events = POLLIN;

  // Ultra-fast stack-allocated ring buffer
  FallbackRing<2048> fallback_ring;

  while (true) {
    uint32_t idx_rx = 0;
    unsigned int rcvd = xsk_ring_cons__peek(&sock->rx, 64, &idx_rx);
    
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

        if (xsk_ring_prod__needs_wakeup(&sock->umen->fq)) {
            poll(fds, 1, 10);
        }
        continue;
    }

    uint64_t batch_bytes = 0;
    for (unsigned int i = 0; i < rcvd; ++i) {
      // Software prefetch the next descriptor ahead into CPU L1 cache
      if (i + 4 < rcvd) {
        AETHON_BUILTIN_PREFETCH(xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i + 4), 0, 1);
      }
      const auto *desc = xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i);
      batch_bytes += desc->len;
      fallback_ring.push(desc->addr);
    }

    // Update global atomic counters (relaxed ordering for low contention)
    total_packets.fetch_add(rcvd, std::memory_order_relaxed);
    total_bytes.fetch_add(batch_bytes, std::memory_order_relaxed);

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

void stats_printer() {
  uint64_t last_packets = 0;
  uint64_t last_bytes = 0;

  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    uint64_t current_packets = total_packets.load(std::memory_order_relaxed);
    uint64_t current_bytes = total_bytes.load(std::memory_order_relaxed);

    uint64_t pps = current_packets - last_packets;
    uint64_t bps = current_bytes - last_bytes;

    double mbps = (bps * 8.0) / 1000000.0; // Megabits per second

    std::cout << "\r[Stats] Speed: " << pps << " pps | " 
              << std::fixed << std::setprecision(2) << mbps << " Mbps" << std::flush;

    last_packets = current_packets;
    last_bytes = current_bytes;
  }
}

int main(int argc, char **argv) {
  const char *ifname = (argc > 1) ? argv[1] : "veth0";
  const char *prog_path = (argc > 2) ? argv[2] : "src/main/xdp_kern_prog.o";

  std::cout << "Starting AF_XDP on interface: " << ifname << "\n";
  std::cout << "Using eBPF Program: " << prog_path << "\n";

  // Initialize all hardware queues
  setup_af_xdp_for_all_queue(ifname, prog_path, "xdp",
                             XDP_MODE_SKB, "aethon_xsks_map");

  int num_queues = aethon::xdp::total_active_queues;
  std::cout << "Running on " << num_queues << " queues...\n";

  // Spawn 1 thread per queue
  std::vector<std::thread> workers;
  
  // Start the statistics printer thread
  workers.emplace_back(stats_printer);

  for (int q = 0; q < num_queues; ++q) {
    workers.emplace_back(rx_worker, q);
  }

  for (auto &w : workers) {
    w.join();
  }

  return 0;
}
