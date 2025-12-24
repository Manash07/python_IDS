# ============================================================
# ICMP Flood Detection IDS
# Live Alert Streaming via Socket.IO
# ============================================================

import subprocess
import socketio
from collections import deque
from datetime import datetime, timezone

# ===================== CONFIG ===================== #

THRESHOLD = 100            # ICMP packets
TIME_WINDOW = 5            # seconds
COOLDOWN = 10              # seconds between alerts per IP
INTERFACE = "any"

BACKEND_SOCKET_URL = "http://localhost:5001"
ATTACK_TYPE = "ICMP_PING_FLOOD"

# ===================== SOCKET.IO CLIENT ===================== #

sio = socketio.Client(reconnection=True)

@sio.event
def connect():
    print("✅ Connected to backend Socket.IO server")

@sio.event
def disconnect():
    print("❌ Disconnected from backend Socket.IO server")

try:
    sio.connect(BACKEND_SOCKET_URL)
except Exception as e:
    print("⚠️ Unable to connect to backend:", e)
    exit(1)

# ===================== DATA STRUCTURES ===================== #

ip_record = {}          # Sliding window timestamps per IP
last_emitted = {}       # Cooldown tracker per IP

# ===================== TSHARK COMMAND ===================== #

cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "icmp.type == 8",
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "ip.src"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("🚀 Live ICMP IDS started...")

# ===================== MAIN LOOP ===================== #

try:
    for line in proc.stdout:
        try:
            timestamp, ip = line.strip().split()
            timestamp = float(timestamp)
        except ValueError:
            continue

        # Initialize queue for new IP
        if ip not in ip_record:
            ip_record[ip] = deque()

        ip_record[ip].append(timestamp)

        # Sliding window cleanup
        while ip_record[ip] and ip_record[ip][0] < timestamp - TIME_WINDOW:
            ip_record[ip].popleft()

        packet_count = len(ip_record[ip])
        print(f"ICMP from {ip} | count={packet_count}")

        # ===================== DETECTION ===================== #

        if packet_count >= THRESHOLD:
            now = datetime.now(timezone.utc)
            last_time = last_emitted.get(ip)

            # Cooldown check
            if not last_time or (now - last_time).total_seconds() >= COOLDOWN:
                alert = {
                    "attack_type": ATTACK_TYPE,
                    "source_ip": ip,
                    "packet_count": packet_count,
                    "time_window": TIME_WINDOW,
                    "severity": "High",
                    "timestamp": now.isoformat(),
                    "message": f"Possible ICMP overflood attack. Please take immediate action"
                }

                # 🔥 Emit live alert to backend 🔥
                sio.emit("live_alert", alert)

                print("🚨 LIVE ALERT SENT:", alert)

                last_emitted[ip] = now
                ip_record[ip].clear()

except KeyboardInterrupt:
    print("\n🛑 Stopping Live ICMP IDS...")

finally:
    proc.terminate()
    sio.disconnect()
    print("✅ IDS shutdown complete")
