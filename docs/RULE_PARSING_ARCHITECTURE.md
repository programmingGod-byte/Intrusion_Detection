# Aethon IDS — Production-Grade Rule Parsing Architecture

> **Status:** Design Specification  
> **Goal:** Make the Aethon rule processing pipeline production-grade, fully Suricata-compatible, and open-source ready.

---

## Table of Contents

1. [The Problem with Naive Parsing](#1-the-problem-with-naive-parsing)
2. [The Two-Phase Engine Architecture](#2-the-two-phase-engine-architecture)
3. [Phase 1: Smart Fast-Pattern Selection (Hyperscan)](#3-phase-1-smart-fast-pattern-selection-hyperscan)
4. [Phase 2: C++ Verification Engine](#4-phase-2-c-verification-engine)
5. [Complete Rule Keyword Support Matrix](#5-complete-rule-keyword-support-matrix)
6. [What PCRE Is and Why It Matters](#6-what-pcre-is-and-why-it-matters)
7. [What Protocol Binary Logic Is and Why It Matters](#7-what-protocol-binary-logic-is-and-why-it-matters)
8. [What Sticky Buffers Are and Why They Matter](#8-what-sticky-buffers-are-and-why-they-matter)
9. [IP/Port Variable Resolution](#9-ipport-variable-resolution)
10. [flowbits and Stateful Tracking](#10-flowbits-and-stateful-tracking)
11. [Production Implementation Plan (Step-by-Step)](#11-production-implementation-plan-step-by-step)
12. [Output JSON Schema (Final Production Format)](#12-output-json-schema-final-production-format)

---

## 1. The Problem with Naive Parsing

The current `parse_rules_to_json.py` + `convert_rules_for_hyperscan.py` pipeline has the following critical flaws:

### Flaw 1: Wrong Primary Content Selection (False Positive Explosion)
```suricata
# Real Suricata Rule:
alert tcp any any -> any 80 (content:"GET"; content:"/login.php"; content:"' OR 1=1--"; fast_pattern; pcre:"/id=\d+'\s*OR/i"; sid:2001;)
```

| What Current Code Does | What Production Code Must Do |
| :--- | :--- |
| Sends `"GET"` to Hyperscan | Send `"' OR 1=1--"` to Hyperscan (marked `fast_pattern`) |
| Triggers on EVERY normal HTTP request | Triggers ONLY when a hacker sends SQLi payload |
| Forces Phase 2 to run millions of times/sec | Phase 2 runs ~0 times/sec for normal traffic |

### Flaw 2: PCRE Discarded
Your converter completely ignores the `pcre` keyword. This turns a surgical rule into a blunt instrument with massive false positive rates.

### Flaw 3: Binary Protocol Keywords Ignored
Keywords like `byte_test`, `byte_jump`, and `isdataat` are silently dropped. This means all DNS, TLS, SMB, and binary protocol attack rules are non-functional.

### Flaw 4: Sticky Buffers Ignored
Rules using `http.uri`, `http.user_agent`, `dns.query`, `tls.sni` target normalized protocol-decoded buffers, not raw packet bytes.

### Flaw 5: `$HOME_NET` / `$EXTERNAL_NET` Not Resolved
Variables like `$HTTP_SERVERS`, `$SQL_SERVERS` are saved as literal strings and never resolved against actual IP ranges.

---

## 2. The Two-Phase Engine Architecture

```
[ Incoming Packet @ 40+ Gbps via AF_XDP ]
                │
                ▼
┌───────────────────────────────────────────────────────────┐
│              Phase 1: Hyperscan Fast-Path                 │
│   - Only the RAREST / fast_pattern content per rule       │
│   - Returns a list of candidate SIDs                      │
│   - Runs on 100% of packets at line rate                  │
└────────────────────────┬──────────────────────────────────┘
                         │
              Candidate SIDs found?
                        ╱ ╲
                      NO   YES (e.g., SID: 2001)
                     ╱       ╲
                    ▼         ▼
             [XDP_PASS]  ┌────────────────────────────────────────┐
                         │        Phase 2: C++ Verifier           │
                         │  (Runs on ~0.001% of packets)          │
                         │                                        │
                         │  Step 1: IP/Port CIDR match            │
                         │  Step 2: offset / depth bounds check   │
                         │  Step 3: byte_test / byte_jump math    │
                         │  Step 4: Negated patterns (!content)   │
                         │  Step 5: PCRE (libpcre2) verification  │
                         │  Step 6: flowbits state check          │
                         └────────────────────┬───────────────────┘
                                              │
                                   Phase 2 passed?
                                            ╱ ╲
                                          NO   YES
                                         ╱       ╲
                                        ▼         ▼
                                 [False Alarm] [REAL ATTACK!]
                                 [XDP_PASS]   [Block IP in eBPF]
```

**Performance Guarantee:** Because `fast_pattern` anchors are always rare/unique strings, normal traffic never triggers Phase 2.

---

## 3. Phase 1: Smart Fast-Pattern Selection (Hyperscan)

### The Fast-Pattern Selection Algorithm

For each Suricata rule with multiple `content` fields, the Python converter must pick exactly ONE as the Hyperscan trigger. Priority order:

#### Priority 1: Explicit `fast_pattern` Keyword
```suricata
content:"GET"; content:"/login"; content:"' OR 1=1"; fast_pattern; sid:100;
```
→ Hyperscan gets: `' OR 1=1`

#### Priority 2: Longest Non-Common String (Rarity Heuristic)
If no `fast_pattern` is specified, pick the content string that:
1. Is the **longest** (rare strings are longer).
2. Does **not** appear in the "Common Skip List".
3. Has the **highest Shannon entropy** (more varied characters = rarer).

#### The Common Skip List (Never Use These as Primary Anchors)
```python
COMMON_SKIP_LIST = {
    # HTTP
    "GET", "POST", "HTTP/1.1", "HTTP/1.0", "HTTP/2",
    "Content-Type:", "User-Agent:", "Host:", "Accept:", 
    "Connection:", "200 OK", "404 Not Found",
    # DNS
    "\x00\x01", "\x00\x01\x00\x01",
    # Generic
    "\r\n", "\r\n\r\n", "\x00", "\xff",
    # TLS
    "\x16\x03", "\x16\x03\x01",
}
```

#### Shannon Entropy Calculator (Higher = Rarer)
```python
import math
from collections import Counter

def entropy(s: str) -> float:
    counts = Counter(s.encode())
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

# "GET"         → entropy: 1.58  (Very low, skip)
# "' OR 1=1--"  → entropy: 3.17  (High, use this!)
# "\x41\xb3\x7f\x02\xde" → entropy: 4.32 (Excellent!)
```

#### Minimum Length Filter
```python
MIN_FAST_PATTERN_LENGTH = 4  # Never use strings shorter than 4 bytes
```

---

## 4. Phase 2: C++ Verification Engine

When Hyperscan fires callback for `SID 2001`, the C++ verifier runs these checks in order. If ANY check fails, the match is discarded as a false positive.

### C++ Rule Metadata Structure
```cpp
struct ByteTest {
    int num_bytes;       // How many bytes to read (e.g., 2)
    std::string op;      // Comparison operator: ">", "<", "==", "!=", "&", "^"
    uint64_t value;      // Value to compare against (e.g., 512)
    int offset;          // Offset in the payload to start reading
    bool relative;       // Is offset relative to last match?
    bool big_endian;     // Network byte order?
};

struct RuleMetadata {
    uint32_t sid;
    std::string proto;           // "tcp", "udp", "dns", "http"
    std::string src_ip_cidr;     // Resolved CIDR: "0.0.0.0/0" or "192.168.0.0/16"
    std::string dst_ip_cidr;
    std::vector<uint16_t> src_ports;
    std::vector<uint16_t> dst_ports;

    // Content verification
    int offset;                  // Absolute search start position
    int depth;                   // Absolute search end position
    std::vector<std::string> negated_patterns;  // Content that must NOT be present

    // Binary protocol checks
    std::vector<ByteTest> byte_tests;

    // PCRE
    bool has_pcre;
    pcre2_code* compiled_pcre;   // Pre-compiled for performance
    std::string pcre_raw;        // For serialization

    // Flowbits
    std::string flowbits_set;    // Bit to set when this rule fires
    std::string flowbits_isset;  // Bit that must already be set
};
```

### C++ Verifier Logic
```cpp
bool verify_rule(const RuleMetadata& meta,
                 const uint8_t* payload, size_t payload_len,
                 const FlowTable& flows, uint64_t flow_key) {

    // Step 1: offset / depth bounds
    if (meta.offset > 0 && payload_len < (size_t)meta.offset)
        return false;
    if (meta.depth > 0 && payload_len > (size_t)meta.depth)
        payload_len = meta.depth;  // Clamp search window

    // Step 2: Negated patterns (!content) — must NOT appear
    for (const auto& neg : meta.negated_patterns) {
        if (memmem(payload, payload_len, neg.data(), neg.size()) != nullptr)
            return false;  // Negated pattern found → false positive
    }

    // Step 3: byte_test (binary math on protocol fields)
    for (const auto& bt : meta.byte_tests) {
        int pos = bt.offset;
        if (bt.relative) pos += last_match_end;  // Relative to previous match
        if (pos + bt.num_bytes > (int)payload_len) return false;

        uint64_t val = 0;
        for (int i = 0; i < bt.num_bytes; i++) {
            val = bt.big_endian ? (val << 8) | payload[pos + i]
                                : val | ((uint64_t)payload[pos + i] << (8 * i));
        }

        if (bt.op == ">"  && !(val >  bt.value)) return false;
        if (bt.op == "<"  && !(val <  bt.value)) return false;
        if (bt.op == "==" && !(val == bt.value)) return false;
        if (bt.op == "!=" && !(val != bt.value)) return false;
        if (bt.op == "&"  && !(val &  bt.value)) return false;
    }

    // Step 4: PCRE verification (libpcre2)
    if (meta.has_pcre) {
        pcre2_match_data* md = pcre2_match_data_create_from_pattern(meta.compiled_pcre, nullptr);
        int rc = pcre2_match(meta.compiled_pcre, payload, payload_len, 0, 0, md, nullptr);
        pcre2_match_data_free(md);
        if (rc < 0) return false;  // PCRE did not match → false positive!
    }

    // Step 5: flowbits check (stateful multi-packet tracking)
    if (!meta.flowbits_isset.empty()) {
        if (!flows.is_set(flow_key, meta.flowbits_isset))
            return false;
    }

    // All checks passed → REAL ATTACK
    if (!meta.flowbits_set.empty())
        flows.set_bit(flow_key, meta.flowbits_set);

    return true;
}
```

---

## 5. Complete Rule Keyword Support Matrix

| Keyword | Category | Current Status | Production Plan |
| :--- | :--- | :--- | :--- |
| `content` | Pattern | ✅ Parsed | Use rarity heuristic to select fast-pattern anchor |
| `fast_pattern` | Pattern | ❌ Ignored | **Must implement:** Forces this content into Hyperscan |
| `nocase` | Pattern | ⚠️ Broken (`(?-i)`) | Fix: Use `HS_FLAG_CASELESS` per-pattern in Hyperscan |
| `offset` | Pattern | ⚠️ Saved, not verified | Implement in Phase 2 C++ bounds check |
| `depth` | Pattern | ⚠️ Saved, not verified | Implement in Phase 2 C++ bounds check |
| `distance` | Pattern | ⚠️ Approximate | Phase 2: verify relative to last match position |
| `within` | Pattern | ⚠️ Approximate | Phase 2: verify window from last match end |
| `pcre` | Pattern | ❌ **Discarded** | **Critical:** Compile with libpcre2, run in Phase 2 |
| `byte_test` | Binary | ❌ **Ignored** | **Critical:** Implement binary math verifier in Phase 2 |
| `byte_jump` | Binary | ❌ **Ignored** | Implement variable-offset jumping in Phase 2 |
| `isdataat` | Binary | ❌ **Ignored** | Implement data boundary check in Phase 2 |
| `http.uri` | Sticky Buffer | ❌ **Ignored** | Requires HTTP parser; search only decoded URI field |
| `http.user_agent` | Sticky Buffer | ❌ **Ignored** | Requires HTTP parser; search only User-Agent header |
| `dns.query` | Sticky Buffer | ❌ **Ignored** | Requires DNS parser; search only query name field |
| `tls.sni` | Sticky Buffer | ❌ **Ignored** | Requires TLS ClientHello parser; search only SNI |
| `flowbits` | State | ❌ **Ignored** | Implement per-flow bitmask table (hash map) |
| `threshold` | Rate | ❌ **Ignored** | Implement per-SID hit counter with time window |
| `sid` | Metadata | ✅ Parsed | Used as rule unique identifier |
| `rev` | Metadata | ✅ Parsed | Used for rule version tracking |
| `msg` | Metadata | ✅ Parsed | Used for alert messages |
| `classtype` | Metadata | ⚠️ Saved | Map to severity levels |
| `priority` | Metadata | ⚠️ Saved | Used for alert severity |
| `metadata` | Metadata | ⚠️ Saved | Parse `affected_product`, `attack_target`, `cve` |

---

## 6. What PCRE Is and Why It Matters

**PCRE = Perl Compatible Regular Expressions.**

In Suricata, a rule uses `content` as a fast, rough filter to check if a packet *might* be malicious, and `pcre` to *prove* it is actually an attack.

### Example: SQL Injection Detection
```suricata
alert tcp any any -> any 80 (
    content:"/login.php";
    pcre:"/id=\d+'\s*(OR|AND)\s+1\s*=\s*1/i";
    sid:2001;
)
```

| Check | Normal User | Hacker |
| :--- | :--- | :--- |
| `content:"/login.php"` | ✅ Matches | ✅ Matches |
| `pcre:"/id=\d+' OR 1=1/i"` | ❌ No match → False Positive Discarded | ✅ Matches → **REAL ATTACK** |

Without PCRE: **Every normal user triggers an alert.**  
With PCRE: **Only the actual hacker is caught.**

### Implementation: Pre-Compile PCRE at Startup
```cpp
#include <pcre2.h>

// During rule loading (once at startup):
int errcode;
PCRE2_SIZE erroffset;
pcre2_code* re = pcre2_compile(
    (PCRE2_SPTR)pcre_string.c_str(),
    PCRE2_ZERO_TERMINATED,
    PCRE2_CASELESS,   // for /i flag
    &errcode,
    &erroffset,
    nullptr
);

// During packet inspection (fast, re-entrant):
pcre2_match_data* md = pcre2_match_data_create_from_pattern(re, nullptr);
int rc = pcre2_match(re, payload, len, 0, 0, md, nullptr);
// rc >= 0 means match found
```

> [!IMPORTANT]
> Always pre-compile PCRE patterns at startup using `pcre2_compile()`. Never call `pcre2_compile()` per-packet — it is extremely slow and will destroy throughput.

---

## 7. What Protocol Binary Logic Is and Why It Matters

Binary protocols (DNS, TLS, DHCP, SMB, Modbus) communicate using raw numbers, length prefixes, and bitflags — **not plain text strings**.

### `byte_test` — Read and Compare a Binary Integer

**Real-World Example (DNS Amplification Detection):**  
A DNS response at byte offset 6 contains a 16-bit integer = number of answers. A DNS response with 500+ answers is likely an amplification attack.

```suricata
alert dns any any -> any any (
    msg:"DNS Amplification Attack";
    byte_test:2, >, 200, 6, big-endian;
    sid:3001;
)
```
*Meaning: Read **2 bytes** at offset **6**, treat as big-endian number, alert if value **> 200**.*

```
DNS Packet Memory Layout:
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│ TxID (2B)│ Flags(2B)│ QdCnt(2B)│ AnCnt(2B)│ NsCnt(2B)│ ArCnt(2B)│
│  0x1234  │  0x8180  │  0x0001  │  0x01F4  │  0x0000  │  0x0000  │
│ Byte 0-1 │ Byte 2-3 │ Byte 4-5 │ Byte 6-7 │ Byte 8-9 │Byte 10-11│
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
                                   ↑
                           byte_test reads here (offset 6)
                           Value: 0x01F4 = 500 → ALERT! (> 200)
```

### `byte_jump` — Jump Over Variable-Length Fields

Binary protocols often have a length byte that tells you how big the next field is.

```suricata
alert tcp any any -> any 445 (
    content:"|FF|SMB";             # Find the SMB signature
    byte_jump:4, 0, relative;     # Read 4-byte length, jump forward that many bytes
    content:"|00|malware_cmd";     # Now search for attack at this new position
    sid:3002;
)
```

Without `byte_jump` support, this rule is completely non-functional.

---

## 8. What Sticky Buffers Are and Why They Matter

Suricata doesn't always search raw packet bytes. For application-layer protocols, it first **normalizes and decodes** protocol fields, then searches those decoded fields.

### The Problem with Raw Byte Matching

A hacker sends this HTTP request to exploit a path traversal vulnerability:
```
GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
Host: target.com
```

The `content:` is looking for `../../etc/passwd`.

| Approach | What It Scans | Does It Match? |
| :--- | :--- | :--- |
| **Raw byte scan (Current)** | `/%2e%2e%2f%2e%2e%2fetc%2fpasswd` | ❌ Miss! (Not the decoded string) |
| **Sticky Buffer http.uri** | `/../../etc/passwd` (URL-decoded) | ✅ Match! |

### Common Sticky Buffers to Implement

| Sticky Buffer | Protocol | What It Contains |
| :--- | :--- | :--- |
| `http.uri` | HTTP | URL-decoded request path |
| `http.user_agent` | HTTP | User-Agent header value |
| `http.request_body` | HTTP | POST body bytes |
| `dns.query` | DNS | Decoded domain name query |
| `tls.sni` | TLS | Server Name Indication field |
| `smtp.from` | SMTP | MAIL FROM address |
| `ssh.software` | SSH | SSH version banner string |

> [!NOTE]
> Implementing all sticky buffers requires writing application-layer protocol parsers. The recommended approach is to prioritize DNS and TLS SNI first, as they are the most common in modern IDS rulesets, and they operate over UDP/TCP without requiring TCP stream reassembly for individual packets.

---

## 9. IP/Port Variable Resolution

Every Suricata rule uses variables like `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_SERVERS`.

These are defined in `suricata.yaml`. Your engine must resolve them before rule compilation.

### Variable Resolution Pipeline

```python
# Default Suricata variable definitions (from suricata.yaml)
SURICATA_VARIABLES = {
    "$HOME_NET":        ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    "$EXTERNAL_NET":    ["!$HOME_NET"],   # Everything NOT in HOME_NET
    "$HTTP_SERVERS":    ["$HOME_NET"],
    "$SMTP_SERVERS":    ["$HOME_NET"],
    "$SQL_SERVERS":     ["$HOME_NET"],
    "$DNS_SERVERS":     ["$HOME_NET"],
    "$HTTP_PORTS":      ["80", "8080", "8000", "8008", "8443"],
    "$SHELL_CODE_PORTS": ["!80"],
    "any":              ["0.0.0.0/0"],    # All IPs
}

def resolve_ip_group(group: str, variables: dict) -> list[str]:
    """Recursively resolve variable references to actual CIDR strings."""
    if group == "any":
        return ["0.0.0.0/0", "::/0"]  # IPv4 + IPv6 any
    if group.startswith("$"):
        return flatten([resolve_ip_group(g, variables) for g in variables.get(group, [])])
    if group.startswith("!"):
        return [f"!{r}" for r in resolve_ip_group(group[1:], variables)]
    if group.startswith("[") and group.endswith("]"):
        # Handle IP groups: [192.168.0.0/16, !10.0.0.0/8]
        return flatten([resolve_ip_group(g.strip(), variables) for g in group[1:-1].split(",")])
    return [group]  # Already a CIDR like "192.168.0.0/16"
```

### Fast IP Matching in C++ (LPM Trie)
```cpp
// Use a Longest-Prefix-Match (LPM) trie for O(1) IP lookups
// Linux kernel API: bpf_map of type BPF_MAP_TYPE_LPM_TRIE
// In userspace C++: use a prefix tree (Patricia trie) or cidr_trie library
bool ip_in_cidr(uint32_t ip, const std::string& cidr) {
    auto [addr, prefix_len] = parse_cidr(cidr);
    uint32_t mask = prefix_len == 0 ? 0 : (~0u << (32 - prefix_len));
    return (ip & mask) == (addr & mask);
}
```

---

## 10. flowbits and Stateful Tracking

Some attacks happen over multiple separate requests. `flowbits` tracks state across packets.

### Example: Detecting Multi-Step Exploits
```suricata
# Rule 1: Detect login failure
alert http any any -> $HTTP_SERVERS any (
    content:"401 Unauthorized";
    flowbits:set,http.auth_fail;
    flowbits:noalert;
    sid:4001;
)

# Rule 2: Alert only if we've seen a previous failure (brute force!)
alert http any any -> $HTTP_SERVERS any (
    content:"POST /login";
    flowbits:isset,http.auth_fail;
    msg:"HTTP Brute Force Attempt";
    sid:4002;
)
```

### C++ Flow Table Implementation
```cpp
#include <unordered_map>
#include <bitset>

// Flow key = hash of (src_ip, dst_ip, src_port, dst_port, proto)
using FlowKey = uint64_t;

struct FlowState {
    std::unordered_map<std::string, bool> bits;
    uint64_t last_seen_ns;
};

class FlowTable {
    std::unordered_map<FlowKey, FlowState> table_;
    
public:
    void set_bit(FlowKey key, const std::string& bit) {
        table_[key].bits[bit] = true;
        table_[key].last_seen_ns = current_time_ns();
    }
    
    bool is_set(FlowKey key, const std::string& bit) const {
        auto it = table_.find(key);
        if (it == table_.end()) return false;
        auto bit_it = it->second.bits.find(bit);
        return bit_it != it->second.bits.end() && bit_it->second;
    }
    
    // Must call periodically: evict flows inactive for > 60 seconds
    void evict_stale_flows(uint64_t timeout_ns = 60'000'000'000ULL) {
        auto now = current_time_ns();
        std::erase_if(table_, [&](const auto& kv) {
            return (now - kv.second.last_seen_ns) > timeout_ns;
        });
    }
};
```

> [!WARNING]
> The FlowTable must be per-thread (one table per AF_XDP worker thread) to avoid cross-thread locking. Because your eBPF program routes all packets from the same 5-tuple to the same queue (via the `ip_hash % num_queues` logic), all packets from one flow will always arrive at the same thread. This guarantees correctness without any mutex locks.

---

## 11. Production Implementation Plan (Step-by-Step)

### Stage 1: Fix Rule Converter (Python)
- [ ] Implement `fast_pattern` keyword detection and prioritization
- [ ] Implement Common Skip List filter
- [ ] Implement Shannon entropy scorer for rarity heuristic
- [ ] Fix `nocase` to output `HS_FLAG_CASELESS` instead of `(?-i)`
- [ ] Extract and save `pcre` patterns to JSON (do NOT discard)
- [ ] Extract and save `byte_test` / `byte_jump` parameters to JSON
- [ ] Implement IP variable resolver (`$HOME_NET` → CIDR list)
- [ ] Extract and save `flowbits` set/isset pairs to JSON
- [ ] Implement sticky buffer tagging (`http.uri`, `dns.query`, etc.)
- [ ] Add minimum length filter (`MIN_FAST_PATTERN_LENGTH = 4`)

### Stage 2: Fix Hyperscan Integration (C++)
- [ ] Use `HS_FLAG_CASELESS` for nocase rules (remove Python `(?-i)`)
- [ ] Use `HS_FLAG_SINGLEMATCH` to stop after first match per SID
- [ ] Use `HS_FLAG_SOM_LEFTMOST` to get match start position for offset/depth verification
- [ ] Allocate Hyperscan scratch space per-thread (`hs_clone_scratch`)

### Stage 3: Build Phase 2 C++ Verifier
- [ ] Build `RuleMetadata` struct with full rule verification parameters
- [ ] Build `ByteTest` executor
- [ ] Integrate libpcre2 for PCRE verification
- [ ] Implement negated pattern checker (`!content`)
- [ ] Implement `offset` / `depth` window enforcement
- [ ] Build `FlowTable` (per-thread, no locks)
- [ ] Build IP/Port CIDR matching (LPM trie or simple prefix check)

### Stage 4: Application-Layer Protocol Parsers
- [ ] Minimal DNS parser (extract query name field for `dns.query` buffer)
- [ ] Minimal TLS ClientHello parser (extract SNI for `tls.sni` buffer)
- [ ] Minimal HTTP/1.1 request parser (extract URI, User-Agent, Body)

### Stage 5: Production Hardening
- [ ] Remove ALL `bpf_printk()` calls from eBPF data path (use perf ring buffer)
- [ ] Replace fixed-size eBPF maps with `BPF_MAP_TYPE_LRU_HASH` (auto-eviction)
- [ ] Implement `FallbackRing` overflow protection (bounded capacity check)
- [ ] Implement `ethtool -L` graceful failure handling (cloud/virtual environments)

---

## 12. Output JSON Schema (Final Production Format)

This is the target JSON schema that the upgraded rule converter should output per rule:

```json
{
  "sid": 2001,
  "rev": 3,
  "msg": "SQL Injection Attempt in Login",
  "action": "alert",
  "proto": "tcp",
  "src_ip": ["0.0.0.0/0"],
  "src_port": ["any"],
  "dst_ip": ["192.168.0.0/16", "10.0.0.0/8"],
  "dst_port": [80, 8080, 443],
  "direction": "->",
  "classtype": "web-application-attack",
  "priority": 1,
  
  "hyperscan": {
    "fast_pattern": "' OR 1=1--",
    "flags": ["HS_FLAG_CASELESS", "HS_FLAG_SINGLEMATCH", "HS_FLAG_SOM_LEFTMOST"],
    "anchor": "fast_pattern_explicit"
  },
  
  "phase2": {
    "offset": 0,
    "depth": 512,
    
    "pcre": {
      "pattern": "/id=\\d+'\\s*(OR|AND)\\s+1\\s*=\\s*1/i",
      "flags": ["PCRE2_CASELESS"]
    },
    
    "contents": [
      {
        "pattern": "GET /login.php",
        "is_fast_pattern": false,
        "negated": false,
        "nocase": false,
        "offset": 0,
        "depth": 100,
        "distance": null,
        "within": null
      },
      {
        "pattern": "' OR 1=1--",
        "is_fast_pattern": true,
        "negated": false,
        "nocase": true,
        "offset": null,
        "depth": null,
        "distance": 0,
        "within": 200
      }
    ],
    
    "negated_patterns": ["safe_user_agent_string"],
    
    "byte_tests": [
      {
        "num_bytes": 2,
        "op": ">",
        "value": 200,
        "offset": 6,
        "relative": false,
        "big_endian": true
      }
    ],
    
    "flowbits": {
      "set": null,
      "isset": "http.auth_fail",
      "unset": null
    },
    
    "sticky_buffer": "http.uri"
  }
}
```

---

## References

- [Suricata Rule Language Documentation](https://suricata.readthedocs.io/en/latest/rules/)
- [Intel Hyperscan Developer Guide](https://intel.github.io/hyperscan/dev-reference/)
- [libpcre2 API Reference](https://www.pcre.org/current/doc/html/pcre2api.html)
- [AF_XDP Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [eBPF BPF Map Types Reference](https://docs.kernel.org/bpf/maps.html)
- Snort 3 Architecture — Pattern Matching Engine Design
- Cloudflare Blog: Detecting Network Anomalies with eBPF

