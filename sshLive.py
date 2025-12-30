import subprocess
import socketio
from collections import deque
from datetime import datetime, timezone

# CONFIG

THRESHOLD = 10            # SSH packets
TIME_WINDOW = 5           # seconds
COOLDOWN = 10             # seconds
INTERFACE = "any"

BACKEND_SOCKET_URL = "http://localhost:5001"
ATTACK_TYPE = "SSH_BRUTE_FORCE"

# SOCKET.IO

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
    print("Socket connection failed:", e)
    exit(1)

# DATA STRUCTURES

ip_record = {}        # { ip: deque[timestamps] }
last_emitted = {}     # cooldown tracking

# ---------------- TSHARK COMMAND ---------------- #

cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "tcp.dstport == 22 and tcp.flags.syn == 1",
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

print("Live SSH IDS started...")

# MAIN LOOP

try:
    for line in proc.stdout:
        try:
            timestamp, ip = line.strip().split()
            timestamp = float(timestamp)
        except ValueError:
            continue

        # Initialize sliding window for IP
        if ip not in ip_record:
            ip_record[ip] = deque()

        ip_record[ip].append(timestamp)

        # Sliding window cleanup
        while ip_record[ip] and ip_record[ip][0] < timestamp - TIME_WINDOW:
            ip_record[ip].popleft()

        count = len(ip_record[ip])
        print(f"SSH attempts from {ip} | count={count}")

        # DETECTION

        if count >= THRESHOLD:
            now = datetime.now(timezone.utc)
            last_time = last_emitted.get(ip)

            if not last_time or (now - last_time).total_seconds() >= COOLDOWN:
                alert = {
                    "attack_type": ATTACK_TYPE,
                    "source_ip": ip,
                    "attempts": count,
                    "time_window": TIME_WINDOW,
                    "severity": "High",
                    "timestamp": now.isoformat(),
                    "message": "Possible SSH brute-force attack detected"
                }

                sio.emit("live_alert", alert)
                print("LIVE ALERT SENT:", alert)

                last_emitted[ip] = now
                ip_record[ip].clear()

except KeyboardInterrupt:
    print("\nStopping SSH IDS...")

finally:
    proc.terminate()
    sio.disconnect()
    print("IDS shutdown complete")
