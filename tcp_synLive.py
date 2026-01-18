import subprocess
import socketio
from collections import defaultdict, deque
from datetime import datetime, timezone

# CONFIG
THRESHOLD = 500           # SYN packets
TIME_WINDOW = 10          # seconds
ALERT_COOLDOWN = 60       # seconds
INTERFACE = "any"
ATTACK_TYPE = "TCP_SYN_FLOOD"
BACKEND_SOCKET_URL = "http://localhost:5001"

# SOCKET.IO CLIENT
sio = socketio.Client(reconnection=True)

@sio.event
def connect():
    print("Connected to backend Socket.IO server")

@sio.event
def disconnect():
    print("Disconnected from backend Socket.IO server")

try:
    sio.connect(BACKEND_SOCKET_URL)
except Exception as e:
    print("Unable to connect to backend:", e)
    exit(1)

# TRACKING STRUCTURES
syn_packets = defaultdict(deque)
last_alert = {}

# TSHARK COMMAND
cmd = [
    "tshark",
    "-n",
    "-l",
    "-i", INTERFACE,
    "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    "-T", "fields",
    "-E", "separator=,",
    "-e", "frame.time_epoch",
    "-e", "ip.src"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1
)

print("Live TCP SYN Flood IDS started (Socket.IO only)...")

# MAIN LOOP
try:
    for line in proc.stdout:
        parts = line.strip().split(",")
        if len(parts) != 2:
            continue

        try:
            timestamp = float(parts[0])
            ip = parts[1]
        except ValueError:
            continue

        syn_packets[ip].append(timestamp)

        # Sliding window cleanup
        while syn_packets[ip] and syn_packets[ip][0] < timestamp - TIME_WINDOW:
            syn_packets[ip].popleft()

        count = len(syn_packets[ip])
        print(f"SYN packets from {ip} | count={count}")

        # DETECTION
        if count >= THRESHOLD:
            now = datetime.now(timezone.utc)
            last_time = last_alert.get(ip)

            # Cooldown check
            if last_time and (now - last_time).total_seconds() < ALERT_COOLDOWN:
                continue

            alert = {
                "attack_type": ATTACK_TYPE,
                "ip": ip,
                "packet_count": count,
                "timestamp": now.isoformat(),
                "message": "High rate of TCP SYN packets detected (possible SYN flood attack)",
                "status": "unresolved"
            }

            # Emit live alert only
            sio.emit("live_alert", alert)
            print("LIVE ALERT SENT:", alert)

            last_alert[ip] = now
            syn_packets[ip].clear()

except KeyboardInterrupt:
    print("\nStopping TCP SYN Flood IDS...")

finally:
    proc.terminate()
    proc.wait()
    sio.disconnect()
    print("IDS shutdown complete")