#include "../af_xdp_header.h"
#include <iostream>
#include <thread>
#include <vector>

#include <chrono>
#include <atomic>
#include <iomanip>

std::atomic<uint64_t> total_packets{0};
std::atomic<uint64_t> total_bytes{0};

#include <poll.h>

void rx_worker(int queue_id) {
  auto *sock = aethon::xdp::xsk_sockets[queue_id].socket_info;
  int sock_fd = xsk_socket__fd(sock->xsk);
  std::cout << "[Queue " << queue_id << "] Worker started\n";

  struct pollfd fds[1];
  fds[0].fd = sock_fd;
  fds[0].events = POLLIN;

  while (true) {
    uint32_t idx_rx = 0;
    unsigned int rcvd = xsk_ring_cons__peek(&sock->rx, 64, &idx_rx);
    
    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(&sock->umen->fq)) {
            poll(fds, 1, 10);
        }
        continue;
    }

    uint64_t batch_bytes = 0;
    for (unsigned int i = 0; i < rcvd; ++i) {
      const auto *desc = xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i);
      batch_bytes += desc->len;
    }

    // Update global counters
    total_packets.fetch_add(rcvd, std::memory_order_relaxed);
    total_bytes.fetch_add(batch_bytes, std::memory_order_relaxed);

    xsk_ring_cons__release(&sock->rx, rcvd);

    uint32_t idx_fq = 0;
    if (xsk_ring_prod__reserve(&sock->umen->fq, rcvd, &idx_fq) == rcvd) {
      for (unsigned int i = 0; i < rcvd; ++i) {
        const auto *desc = xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i);
        *xsk_ring_prod__fill_addr(&sock->umen->fq, idx_fq + i) = desc->addr;
      }
      xsk_ring_prod__submit(&sock->umen->fq, rcvd);
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
