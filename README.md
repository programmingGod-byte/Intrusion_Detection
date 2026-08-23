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
  └───────────────────────────────────────────────────────┘
```

### **1. Tier 1: Volumetric DDoS Mitigation (Kernel space)**
* **Component:** `af_xdp_kern.c`
* **Mechanism:** Checks the source IP of every incoming packet against a shared BPF Hash Map (`blacklist_map`).
* **Performance:** If matched, it returns `XDP_DROP` immediately at the network driver level. This runs in **~10 nanoseconds**, discarding millions of malicious packets before they consume CPU or RAM allocations.

### **2. Tier 2: Stateful Load Balancing (Kernel space)**
* **Component:** `af_xdp_kern.c`
* **Mechanism:** Routes standard verified traffic or non-HTTP traffic directly to target backend servers by rewriting MAC/IP addresses and utilizing `XDP_TX` (hairpin routing). It forwards HTTP packets (TCP Port 80/443) to user-space for inspection.

### **3. Tier 3: Zero-Copy Intrusion Prevention (User-space)**
* **Component:** `af_xdp_user.c`
* **Mechanism:** Receives packets from the network interface queue directly into page-aligned **UMEM** via DMA with **zero memory copies**. A multi-threaded engine parses headers (Ethernet, IPv4, TCP/UDP, ICMP, ARP, DNS) and runs string-matching searches on the payloads.
* **IP Blocking Feedback Loop:** If an exploit (like SQL Injection `"1=1"`) is detected, the program drops the packet and adds the attacker's IP to the kernel's BPF `blacklist_map`. Subsequent packets from that attacker are blocked in Tier 1 at line rate.

---

## 🗄️ Attack Signature Resources

To populate your pattern search trees (e.g. Aho-Corasick or string match engines) with realistic signatures for HTTP, DNS, ICMP, and ARP, use the following open-source databases:

### **1. HTTP & Web Attacks (WAF)**
* **Database:** [OWASP ModSecurity Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset)
* **Description:** The industry standard for web application protection.
* **Target Files (in the `rules/` directory):**
  * `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (SQL Injection regex)
  * `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (Cross-Site Scripting signatures)
  * `REQUEST-932-APPLICATION-ATTACK-RCE.conf` (Remote Code Execution commands)

### **2. Network Protocols (DNS, ICMP, ARP, TCP)**
* **Database:** [Emerging Threats (ET) Open Rules](https://rules.emergingthreats.net/open/)
* **Description:** Community-maintained rules for Suricata and Snort.
* **Target Files (in the `rules/` directory):**
  * `emerging-dns.rules` (DNS Tunneling patterns, malformed queries, cache poisoning)
  * `emerging-icmp.rules` (Ping of Death, ICMP redirect payloads)
  * `emerging-malware.rules` (Active command & control payloads)

### **3. Raw Exploit Payloads (Testing)**
* **Database:** [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* **Description:** A comprehensive repository of raw security bypass payloads.
* **Target Folders:**
  * `SQL Injection/` (Flat lists of SQL evasion bypass strings)
  * `XSS/` (Lists of obfuscated JavaScript payloads)

---

## 🛠️ Build and Run

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
