# High-Performance AF_XDP Security Pipeline

This project implements a high-performance network security engine leveraging Linux **eBPF/XDP (eXpress Data Path)** and **AF_XDP Zero-Copy sockets**. It is designed to operate as a low-latency **DDoS Mitigator**, **Load Balancer**, and **Intrusion Prevention System (IPS)**.

---

## 🏗️ System Architecture

To process packets at line rate without degrading system performance, the pipeline splits responsibilities into three distinct tiers across the Kernel and User-space boundaries:

```
                     [ Incoming Traffic ]
                              │
  ┌───────────────────────────┴───────────────────────────┐
  │  TIER 1: DDoS Prevention (Kernel BPF)                 │
  │  - Instantly drops blacklisted IPs (XDP_DROP)         │
  │  - Mitigates volumetric floods (SYN/UDP floods)       │
  └───────────────────────────┬───────────────────────────┘
                              ▼
  ┌───────────────────────────────────────────────────────┐
  │  TIER 2: Load Balancer / Routing (Kernel BPF)         │
  │  - Forwards non-inspected traffic via XDP_TX          │
  │  - Redirects target HTTP traffic to AF_XDP Socket     │
  └───────────────────────────┬───────────────────────────┘
                              ▼
  ┌───────────────────────────────────────────────────────┐
  │  TIER 3: Web Application Firewall / IPS (User-Space)   │
  │  - Performs deep packet inspection (DPI)              │
  │  - Scans TCP/UDP payloads (SQLi, XSS, DNS Tunneling)  │
  │  - If Clean: Zero-Copy forwards to backend via TX Ring │
  │  - If Malicious: Drops packet + Blacklists IP in BPF  │
  └───────────────────────────┬───────────────────────────┘
```

### **1. Tier 1: Volumetric DDoS Mitigation (Kernel space)**

- **Component:** `af_xdp_kern.c`
- **Mechanism:** Checks the source IP of every incoming packet against a shared BPF Hash Map (`blacklist_map`).
- **Performance:** If matched, it returns `XDP_DROP` immediately at the network driver level. This runs in **~10 nanoseconds**, discarding millions of malicious packets before they consume CPU or RAM allocations.

### **2. Tier 2: Stateful Load Balancing (Kernel space)**

- **Component:** `af_xdp_kern.c`
- **Mechanism:** Routes standard verified traffic or non-HTTP traffic directly to target backend servers by rewriting MAC/IP addresses and utilizing `XDP_TX` (hairpin routing). It forwards HTTP packets (TCP Port 80/443) to user-space for inspection.

### **3. Tier 3: Zero-Copy Intrusion Prevention (User-space)**

- **Component:** `af_xdp_user.c`
- **Mechanism:** Receives packets from the network interface queue directly into page-aligned **UMEM** via DMA with **zero memory copies**. A multi-threaded engine parses headers (Ethernet, IPv4, TCP/UDP, ICMP, ARP, DNS) and runs string-matching searches on the payloads.
- **IP Blocking Feedback Loop:** If an exploit (like SQL Injection `"1=1"`) is detected, the program drops the packet and adds the attacker's IP to the kernel's BPF `blacklist_map`. Subsequent packets from that attacker are blocked in Tier 1 at line rate.

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
