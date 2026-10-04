let autoScroll = true;
let kLen = 0, cLen = 0;
let stats = { blocked: 0, listed: 0, triggered: 0, packets: 0 };

function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function fetchLogs() {
    try {
        // --- Kernel Logs ---
        const r1 = await fetch('/api/logs/kernel');
        const kLogs = await r1.json();
        
        if (kLogs.length !== kLen) {
            const kArea = document.getElementById('kernel-terminal');
            const newK = kLogs.slice(kLen);
            kLen = kLogs.length;

            stats = { blocked: 0, listed: 0, triggered: 0, packets: 0 };
            for (const l of kLogs) {
                if (l.type === 'blocked') stats.blocked++;
                if (l.type === 'blocklisted') stats.listed++;
                if (l.type === 'trigger') stats.triggered++;
                if (l.type === 'packet') stats.packets++;
            }
            document.getElementById('stat-blocked').textContent = stats.blocked;
            document.getElementById('stat-listed').textContent = stats.listed;
            document.getElementById('stat-triggered').textContent = stats.triggered;
            document.getElementById('stat-packets').textContent = stats.packets;

            for (const l of newK) {
                const div = document.createElement('div');
                div.innerHTML = `<span class="log-time">[${l.time}]</span><span class="type-${l.type}">${esc(l.raw)}</span>`;
                kArea.appendChild(div);
            }
            if (autoScroll) kArea.scrollTop = kArea.scrollHeight;
        }

        // --- Command Logs ---
        const r2 = await fetch('/api/logs/cmd');
        const cLogs = await r2.json();
        
        if (cLogs.length !== cLen) {
            const cArea = document.getElementById('cmd-terminal');
            const newC = cLogs.slice(cLen);
            cLen = cLogs.length;

            for (const l of newC) {
                const div = document.createElement('div');
                div.innerHTML = `<span class="log-time">[${l.time}]</span><span class="type-${l.type}">${esc(l.raw)}</span>`;
                cArea.appendChild(div);
            }
            if (autoScroll) cArea.scrollTop = cArea.scrollHeight;
        }
    } catch (e) {
        console.error("Failed to fetch logs", e);
    }
}

async function fetchStatus() {
    try {
        const r = await fetch('/api/status');
        const s = await r.json();
        const ind = document.getElementById('status-indicator');
        if (s.running) {
            ind.innerHTML = `<div class="w-2 h-2 rounded-full bg-[#f85149] animate-pulse"></div> ATTACK ACTIVE`;
            ind.className = 'text-xs font-mono text-[#f85149] flex items-center gap-1.5';
        } else {
            ind.innerHTML = `<div class="w-2 h-2 rounded-full bg-[#3fb950]"></div> IDLE`;
            ind.className = 'text-xs font-mono text-[#3fb950] flex items-center gap-1.5';
        }
    } catch (e) {}
}

async function launch(type) {
    const payload = {
        type,
        target_ip: document.getElementById('target-ip').value.trim(),
        iface: document.getElementById('attack-iface').value.trim(),
    };

    if (type === 'tcp_frag') payload.count = document.getElementById('frag-count').value;
    if (type === 'syn_same') payload.packets = document.getElementById('syn-same-pkts').value;
    if (type === 'syn_multi') {
        payload.num_ips = document.getElementById('syn-multi-ips').value;
        payload.packets = document.getElementById('syn-multi-pkts').value;
    }

    fetch('/api/attack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
}

async function stopAttack() { fetch('/api/stop', { method: 'POST' }); }
async function setupVeth() { fetch('/api/setup_veth', { method: 'POST' }); }

async function clearKernel() {
    await fetch('/api/clear', { method: 'POST' });
    document.getElementById('kernel-terminal').innerHTML = '';
    kLen = 0;
}
async function clearCmd() {
    await fetch('/api/clear', { method: 'POST' });
    document.getElementById('cmd-terminal').innerHTML = '';
    cLen = 0;
}

function toggleScroll() {
    autoScroll = !autoScroll;
    const btn = document.getElementById('scroll-btn');
    if (autoScroll) {
        btn.textContent = 'AUTO-SCROLL: ON';
        btn.className = 'text-[10px] font-semibold text-[#58a6ff] hover:text-white transition-colors';
    } else {
        btn.textContent = 'AUTO-SCROLL: OFF';
        btn.className = 'text-[10px] font-semibold text-[#8b949e] hover:text-white transition-colors';
    }
}

setInterval(fetchLogs, 500);
setInterval(fetchStatus, 1000);
fetchLogs();
fetchStatus();
