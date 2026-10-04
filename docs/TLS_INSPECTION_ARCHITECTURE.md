# TLS Inspection Architecture and Load Balancer Dynamics

## 1. The Load Balancer TLS Termination Architecture

In modern enterprise networks, the Load Balancer (or Reverse Proxy/API Gateway) is usually the component that decrypts TLS traffic. This is called **TLS Termination**.

```
Internet (Encrypted)
       │
       ▼
[ Hardware/Cloud Load Balancer ] (e.g., F5 BIG-IP, AWS ALB, Nginx)
       │  ← TLS TERMINATION HAPPENS HERE
       │
       ▼
[ Internal Network (Plaintext HTTP) ]
       │
       ▼
[ Web Server ] (e.g., Node.js, Python, Java)
```

### Where Does Aethon Fit In?

If Aethon is placed **behind** the Load Balancer (on the internal network), **it does not need to decrypt anything**. The Load Balancer has already removed the TLS encryption. Aethon will see pure, unencrypted HTTP traffic and can run full Suricata rules at maximum speed.

If Aethon is placed **in front of** or **on** the Load Balancer (e.g., Aethon running on the same Linux machine as Nginx/HAProxy):
- The traffic entering the server via AF_XDP is still encrypted.
- The userspace proxy (Nginx) will decrypt it *after* Aethon inspects the raw packets.

## 2. Real-Time TLS Decryption Performance (CPU vs GPU)

If you choose to decrypt TLS directly inside Aethon (acting as an inline transparent proxy or using `SSLKEYLOGFILE`), here is the performance reality:

### CPU Decryption (AES-NI)
Modern CPUs have dedicated hardware instructions for AES encryption (`AES-NI`).
- **Speed:** A single modern CPU core (e.g., AMD EPYC or Intel Xeon) can decrypt AES-128-GCM at roughly **2–4 Gbps**.
- **Cost:** To decrypt 10 Gbps of traffic, you need **3 to 5 dedicated CPU cores** doing nothing but math.
- **Verdict:** Doable, but expensive. It eats up CPU cycles that should be used for Hyperscan pattern matching.

### GPU Decryption (CUDA / Hardware Offload)
Can you send the encrypted packets to an NVIDIA GPU to decrypt them?
- **Speed:** A high-end GPU can mathematically decrypt AES at **40–100+ Gbps**.
- **The PCIe Bottleneck:** The problem is moving the data. To decrypt on a GPU, the packet journey is:
  `NIC -> CPU RAM -> PCIe Bus -> GPU RAM -> Decrypt -> PCIe Bus -> CPU RAM`
- **Latency:** Transferring small 1500-byte packets across the PCIe bus to the GPU and back introduces massive latency (often hundreds of microseconds per batch) and destroys the zero-copy advantage of AF_XDP.
- **Verdict:** GPUs are terrible for low-latency streaming packet decryption. They are only good if you batch thousands of packets together, which delays inspection.

### Smart NICs / DPU Decryption (The Industry Standard)
The modern solution is **Data Processing Units (DPUs)** or SmartNICs (e.g., NVIDIA BlueField, AWS Nitro, Intel IPU).
- These network cards have dedicated cryptography ASICs built directly into the silicon.
- **Speed:** They decrypt TLS at **100–400 Gbps line-rate** *before* the packet even reaches the host CPU's PCIe bus.
- **Verdict:** This is how AWS and Cloudflare do it. The NIC decrypts the traffic in hardware, and AF_XDP receives plaintext packets.

## 3. The Final Recommendation for Aethon

Do not try to build a software TLS decryption engine inside Aethon using CPU or GPU math. It will destroy your 10+ Gbps throughput goal.

**The production-grade deployment strategy:**
1. Deploy Aethon **behind** the Load Balancer (inspecting plaintext internal traffic).
2. Or, deploy Aethon on a server with a **SmartNIC/DPU** that handles hardware TLS offload.
3. If deployed on the edge (encrypted traffic), use Aethon for **TLS Metadata Inspection (JA3, SNI, Certificates)** and **eBPF DDoS/Fragment blocking**, leaving payload decryption to the dedicated proxy.
