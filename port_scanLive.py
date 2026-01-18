import subprocess
import socketio
from collections import defaultdict, deque
from datetime import datetime, timezone

# CONFIG
PORT_THRESHOLD = 20      # unique ports
TIME_WINDOW = 5          # seconds
ALERT_COOLDOWN = 60
INTERFACE = "any"
ATTACK_TYPE = "PORT_SCAN"
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

# TRACKING STRUCTURE
# src_ip -> deque of (timestamp, dst_port)
scan_activity = defaultdict(deque)
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
    "-e", "ip.src",
    "-e", "tcp.dstport"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1
)

print("Live TCP Port Scan IDS started...")

# MAIN LOOP
try:
    for line in proc.stdout:
        parts = line.strip().split(",")
        if len(parts) != 3:
            continue

        try:
            timestamp = float(parts[0])
            src_ip = parts[1]
            dst_port = int(parts[2])
        except ValueError:
            continue

        scan_activity[src_ip].append((timestamp, dst_port))

        # Sliding window cleanup
        while scan_activity[src_ip] and scan_activity[src_ip][0][0] < timestamp - TIME_WINDOW:
            scan_activity[src_ip].popleft()

        # Count unique destination ports
        unique_ports = {p for _, p in scan_activity[src_ip]}
        port_count = len(unique_ports)

        print(f"Port scan check {src_ip} | unique ports={port_count}")

        # DETECTION
        if port_count >= PORT_THRESHOLD:
            now = datetime.now(timezone.utc)
            last_time = last_alert.get(src_ip)

            if last_time and (now - last_time).total_seconds() < ALERT_COOLDOWN:
                continue

            alert = {
                "attack_type": ATTACK_TYPE,
                "ip": src_ip,
                "ports_scanned": sorted(unique_ports),
                "port_count": port_count,
                "timestamp": now.isoformat(),
                "message": "Multiple TCP ports probed in short time (possible port scan)",
                "status": "unresolved"
            }

            sio.emit("live_alert", alert)
            print("LIVE PORT SCAN ALERT:", alert)

            last_alert[src_ip] = now
            scan_activity[src_ip].clear()

except KeyboardInterrupt:
    print("\nStopping Port Scan IDS...")

finally:
    proc.terminate()
    proc.wait()
    sio.disconnect()
    print("IDS shutdown complete")
