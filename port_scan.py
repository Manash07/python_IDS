import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# ENV
load_dotenv(dotenv_path="/home/manash/Desktop/networkids/python/.env", override=True)
MONGO_URI = os.getenv("MONGO_URI")

# CONFIG
PORT_THRESHOLD = 15      # unique ports
TIME_WINDOW = 10         # seconds
ALERT_COOLDOWN = 60      # seconds
INTERFACE = "any"

# MongoDB
client = MongoClient(MONGO_URI)
db = client["alert_db"]
collection = db["alerts"]

# Tracking
# ip → deque of (timestamp, dst_port)
ip_ports = defaultdict(deque)
last_alert = {}

# TSHARK
cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "tcp.dstport"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("Port Scan Detection Started...")

# MAIN LOOP
try:
    for line in proc.stdout:
        try:
            timestamp, ip, port = line.strip().split()
            timestamp = float(timestamp)
            port = int(port)
        except ValueError:
            continue

        ip_ports[ip].append((timestamp, port))

        # Sliding window cleanup
        while ip_ports[ip] and ip_ports[ip][0][0] < timestamp - TIME_WINDOW:
            ip_ports[ip].popleft()

        # Count unique ports
        unique_ports = {p for _, p in ip_ports[ip]}
        count = len(unique_ports)

        print(f"Scan activity from {ip} | unique ports={count}")

        if count >= PORT_THRESHOLD:
            now = datetime.now(timezone.utc)

            # Cooldown check
            if ip in last_alert:
                if (now - last_alert[ip]).total_seconds() < ALERT_COOLDOWN:
                    continue

            alert = {
                "type": "alert",
                "attack": "Port Scan",
                "ip": ip,
                "timestamp": now,
                "message": f"Multiple ports probed in a short time (possible reconnaissance activity)",
                "status": "unresolved"
            }

            collection.insert_one(alert)
            last_alert[ip] = now

            print("ALERT STORED:", alert)

except KeyboardInterrupt:
    print("\nStopping Port Scan Detection...")

finally:
    proc.terminate()
    proc.wait()
    client.close()
