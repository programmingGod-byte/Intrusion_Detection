# High-Performance AF_XDP Security Pipeline

This project implements a high-performance network security engine leveraging Linux **eBPF/XDP (eXpress Data Path)** and **AF_XDP Zero-Copy sockets**. It is designed to operate as a low-latency **DDoS Mitigator**, **Load Balancer**, and **Intrusion Prevention System (IPS)**.

---

### 🏗️ System Architecture (Dual-Plane Design)

To process packets at line rate without degrading system performance, Aethon XDP-Sentinel splits responsibilities into a **Data Plane** (Kernel eBPF) and an **Analytics/Control Plane** (User-space C++), connected via highly optimized BPF Maps and AF_XDP Zero-Copy rings.

```text
                     [ Incoming Traffic ]
                              │
  ┌───────────────────────────┴───────────────────────────┐
  │  DATA PLANE: XDP Kernel space (af_xdp_kern.c)         │
  │  - Parses Eth/IP/TCP headers using pointer arithmetic │
  │  - Checks `ip_blocklist` BPF map (O(1) lookup)        │
  │  - Applies Token Bucket rate limiting via BPF maps    │
  │  - Drops Malicious Packets instantly (XDP_DROP)       │
  │  - Redirects suspicious/HTTP traffic to User-space    │
  └───────────────────────────┬───────────────────────────┘
                              ▼ (AF_XDP RX Ring - Zero Copy DMA)
  ┌───────────────────────────┴───────────────────────────┐
  │  ANALYTICS PLANE: User-space C++ (af_xdp_user.c)      │
  │  - Receives packets via AF_XDP into UMEM              │
  │  - EWMA Spike Detection for sudden traffic bursts     │
  │  - SIMD (AVX2) Payload Parsing & Signature Matching   │
  │  - Updates `ip_blocklist` Map for closed-loop block   │
  │  - io_uring for async, zero-syscall disk logging      │
  └───────────────────────────┬───────────────────────────┘
```

### 🧠 How It's Implemented: Component Breakdown

#### 1. eBPF / XDP Data Plane (`af_xdp_kern.c`)
- **Execution:** Runs directly in the NIC driver. Executes in nanoseconds.
- **BPF Maps:**
  - `ip_blocklist` (`BPF_MAP_TYPE_HASH`): Maps Source IP to an expiration timestamp. If XDP sees an IP in this map, it instantly returns `XDP_DROP`.
  - `ip_counters` (`BPF_MAP_TYPE_PERCPU_HASH`): Stores `packet_count` and `last_updated`. Used to track traffic rates per IP.
  - `admin_config` (`BPF_MAP_TYPE_ARRAY`): Allows the user-space administrator to dynamically adjust the global rate limit (e.g., 60 packets/sec).
- **Rate Limiting:** Implements a Token Bucket algorithm inside the kernel. If an IP exceeds the token limit within a timeframe, packets are dropped.

#### 2. AF_XDP Zero-Copy Pipeline
- Instead of using standard Linux sockets (which require memory copies and context switches), unhandled or suspicious packets are sent directly to user-space memory (UMEM) via **AF_XDP**.
- The `AF_XDP` sockets use lock-free rings (RX, TX, FILL, COMPLETION) to pass packet offsets between the kernel and the C++ application.

#### 3. Spike Detection via EWMA (User-space Analytics, `af_xdp_user.c`)
- The C++ analytics engine computes an **Exponentially Weighted Moving Average (EWMA)** of traffic per IP using fast bitwise shifts instead of floating-point math:
  `old_ewma = old_ewma - (old_ewma >> 3) + (current_rate >> 3);`
- If the `current_rate` suddenly spikes beyond the EWMA (e.g., a 3x multiplier), the engine flags the IP as anomalous and dynamically writes it into the `ip_blocklist` BPF Map. The next packet from that IP is instantly dropped by the kernel.

#### 4. SIMD (AVX2) Deep Packet Inspection (`af_xdp_user.c`)
- For HTTP/DNS traffic, the payload must be inspected for signatures (like SQL injection `1=1` or XSS scripts).
- Standard string searching is too slow for 10Gbps+ networks.
- Aethon utilizes **AVX2 SIMD Intrinsics** (`_mm256_cmpeq_epi8`, `_mm256_movemask_epi8`) to search 32 bytes of payload simultaneously in a single CPU cycle. It flattens Aho-Corasick automata into SIMD-friendly vector operations.

#### 5. io_uring Asynchronous Logging
- Every dropped packet or blocked IP must be logged for auditing.
- Standard file I/O (`write()`) involves expensive syscalls and thread blocking.
- Aethon uses **`io_uring` in SQPOLL (Zero-Syscall) mode** to asynchronously flush logs to disk. The C++ app enqueues log entries into a lock-free submission queue, and a kernel thread writes them to disk in the background, achieving millions of log events per second with zero application overhead.

#### 6. Lock-Free Concurrency (`aethon::MpmcQueue`, `aethon::SpscQueue`)
- To scale across multiple CPU cores, the system distributes packet processing tasks among worker threads.
- Instead of standard mutexes (which cause context-switch latency), thread communication relies on **Aethon's Lock-Free queues**. Bounded queues use atomic compare-and-swap (CAS) and memory barriers (`std::memory_order_release` / `acquire`) to achieve sub-20-nanosecond inter-thread latencies.

---

## 🗄️ Attack Signature Resources

To populate your pattern search trees (e.g. Aho-Corasick or string match engines) with realistic signatures for HTTP, DNS, ICMP, and ARP, use the following open-source databases:

### **1. HTTP & Web Attacks (WAF)**

- **Database:** [OWASP ModSecurity Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset)
- **Description:** The industry standard for web application protection.
- **Target Files (in the `rules/` directory):**
  - `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (SQL Injection regex)
  - `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (Cross-Site Scripting signatures)
  - `REQUEST-932-APPLICATION-ATTACK-RCE.conf` (Remote Code Execution commands)

### **2. Network Protocols (DNS, ICMP, ARP, TCP)**

- **Database:** [Emerging Threats (ET) Open Rules](https://rules.emergingthreats.net/open/)
- **Description:** Community-maintained rules for Suricata and Snort.
- **Target Files (in the `rules/` directory):**
  - `emerging-dns.rules` (DNS Tunneling patterns, malformed queries, cache poisoning)
  - `emerging-icmp.rules` (Ping of Death, ICMP redirect payloads)
  - `emerging-malware.rules` (Active command & control payloads)

### **3. Raw Exploit Payloads (Testing)**

- **Database:** [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- **Description:** A comprehensive repository of raw security bypass payloads.
- **Target Folders:**
  - `SQL Injection/` (Flat lists of SQL evasion bypass strings)
  - `XSS/` (Lists of obfuscated JavaScript payloads)

---

## 🛠️ Build and Run AF_XDP Pipeline

### **Prerequisites**

Install the eBPF development libraries:

```bash
sudo apt-get install libbpf-dev libxdp-dev clang llvm gcc make
```

### **Compilation**

Compile the kernel BPF program and the user-space controller:

```bash
make
```

### **Execution**

Run the pipeline by binding the socket to your network interface (e.g. `eth0` or `veth0`):

```bash
sudo ./af_xdp_user <interface_name>
```

---

## ⚡ Aethon HFT Container Performance Benchmarks

All benchmarks are measured using CPU timestamp counters (`rdtsc`) with CPU core pinning (`pthread_setaffinity_np`) and `SCHED_FIFO` real-time scheduling on Linux (`sudo ./benchmark`).

### **Raw Benchmark Terminal Output:**

```text
=====================================================
  AETHON HIGH-PERFORMANCE SUITE RDTSC BENCHMARKS
=====================================================

----------------------------------------
  Benchmarking std::deque + mutex (10M Ops) [Pinned Core 2 & 3]
----------------------------------------
std::deque Total CPU Cycles: 3516109960 cycles
std::deque Avg Cycles / Op : 351.611 cycles/op

----------------------------------------
  Benchmarking SPSC Queue (10M Ops) [Pinned Core 2 & 3]
----------------------------------------
SPSC Total CPU Cycles: 181523856 cycles
SPSC Avg Cycles / Op : 18.1524 cycles/op

----------------------------------------
  Benchmarking MPMC Queue (10M Ops) [Pinned Core 2 & 3]
----------------------------------------
MPMC Total CPU Cycles: 337977960 cycles
MPMC Avg Cycles / Op : 34.3978 cycles/op

----------------------------------------
  Benchmarking std::array (100M Short-Lived Arrays) [Pinned Core 2]
----------------------------------------
std::array Total Cycles: 154365224 cycles
std::array Avg Cycles / Array (4 items): 1.54365 cycles/op

----------------------------------------
  Benchmarking std::vector (100M Short-Lived Vectors) [Pinned Core 2]
----------------------------------------
std::vector Total Cycles: 9437069820 cycles
std::vector Avg Cycles / Vector (4 items): 94.3707 cycles/op

----------------------------------------
  Benchmarking aethon::SmallVector (100M Short-Lived Vectors) [Pinned Core 2]
----------------------------------------
aethon::SmallVector Total Cycles: 271116068 cycles
aethon::SmallVector Avg Cycles / Vector (4 items): 2.71116 cycles/op

----------------------------------------
  Benchmarking std::unordered_map + mutex (10M Concurrent Ops, 4 Threads)
----------------------------------------
std::unordered_map Total Cycles: 5749223434 cycles
std::unordered_map Avg Cycles / Insert: 574.922 cycles/op

----------------------------------------
  Benchmarking aethon::LockFreeHashMap (10M Concurrent Ops, 4 Threads)
----------------------------------------
aethon::LockFreeHashMap Total Cycles: 849499644 cycles
aethon::LockFreeHashMap Avg Cycles / Insert: 84.95 cycles/op

=====================================================
  ALL BENCHMARKS COMPLETED SUCCESSFULLY!
=====================================================
```

### 📊 **Performance Summary Matrix**

| Category                            | Standard C++ / Naive Implementation                   | Aethon High-Performance Container                             | Latency Reduction  | Speed Multiplier       |
| :---------------------------------- | :---------------------------------------------------- | :------------------------------------------------------------ | :----------------- | :--------------------- |
| **SPSC Queue (1 Thread Pair)**      | `std::deque` + `std::mutex` (**351.61 cycles/op**)    | `aethon::detail::ProducerConsumerQueue` (**18.15 cycles/op**) | **-94.8% Latency** | ⚡ **~19.37x Faster**  |
| **MPMC Queue (1 Thread Pair)**      | `std::deque` + `std::mutex` (**351.61 cycles/op**)    | `aethon::MpmcQueue` (**33.80 cycles/op**)                     | **-90.4% Latency** | ⚡ **~10.40x Faster**  |
| **Small Vector (4 items)**          | `std::vector` (**94.37 cycles/op**)                   | `aethon::SmallVector<T, 4>` (**2.71 cycles/op**)              | **-97.1% Latency** | ⚡ **~34.81x Faster**  |
| **Baseline Stack Array**            | `std::array<T, 4>` (**1.54 cycles/op**)               | `aethon::SmallVector<T, 4>` (**2.71 cycles/op**)              | Near Stack Speed   | Dynamic Growth Support |
| **Concurrent Hash Map (4 Threads)** | `std::unordered_map` + `mutex` (**574.92 cycles/op**) | `aethon::LockFreeHashMap` (**84.95 cycles/op**)               | **-85.2% Latency** | ⚡ **~6.77x Faster**   |

### 🛠️ **Build & Run Aethon Benchmarks**

```bash
# Navigate to directory
cd /home/shivam/Desktop/learning/advanceCpp/Aethon

# Compile with full -O3 optimizations
g++ -O3 -std=c++20 -DAETHON_NO_MAIN -Wno-interference-size -I. benchmark.cpp -o benchmark -lpthread

# Run benchmark suite with real-time OS permissions
sudo ./benchmark
```

## Academic Research & Architecture References
The Aethon architecture is heavily inspired by the following foundational papers in high-performance networking and DPI:

* **The Security Foundation (TCP Evasion):**
  [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](https://users.ece.cmu.edu/~adrian/731-sp04/readings/Ptacek-Newsham-ids98.pdf) (Ptacek & Newsham, 1998)
* **User-Space TCP Architecture:**
  [mTCP: a Highly Scalable User-level TCP Stack for Multicore Systems](https://www.usenix.org/system/files/conference/nsdi14/nsdi14-paper-jeong.pdf) (NSDI '14)
* **GPU-Accelerated DPI:**
  [Kargus: A Highly-Scalable Software-based Intrusion Detection System](https://dl.acm.org/doi/pdf/10.1145/2382196.2382232) (ACM CCS '12)
* **Modern eBPF/XDP Edge Architecture:**
  [Unimog: Cloudflare's Edge Load Balancer](https://blog.cloudflare.com/unimog-cloudflares-edge-load-balancer/) (Cloudflare Engineering)
