import subprocess
from collections import deque, defaultdict
from datetime import datetime, timezone
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# ------------------ ENV ------------------ #
load_dotenv(dotenv_path="/home/manash/Desktop/networkids/python/.env", override=True)

MONGO_URI = os.getenv("MONGO_URI")

# ------------------ CONFIG ------------------ #
threshold = 20        # packets in window
time_window = 10      # seconds
interface = "any"

# ------------------ MongoDB ------------------ #
client = MongoClient(MONGO_URI)
collection = client["alert_db"]["alerts"]

# ------------------ SSH Tracking ------------------ #
ip_packets = defaultdict(deque)
last_alert_time = {}
ALERT_COOLDOWN = 60  # seconds

cmd = [
    "tshark",
    "-i", interface,
    "-Y", "tcp.port == 22",
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

print("🔍 SSH brute-force monitoring started...")

try:
    for line in proc.stdout:
        try:
            tst, ip = line.strip().split()
            tst = float(tst)
        except ValueError:
            continue

        ip_packets[ip].append(tst)

        # Sliding window cleanup
        while ip_packets[ip] and ip_packets[ip][0] < tst - time_window:
            ip_packets[ip].popleft()

        print(f"SSH traffic from {ip} | count={len(ip_packets[ip])}")

        if len(ip_packets[ip]) >= threshold:
            now = datetime.now(timezone.utc)

            # Cooldown
            if ip in last_alert_time:
                if (now - last_alert_time[ip]).total_seconds() < ALERT_COOLDOWN:
                    continue

            alert = {
                "type": "alert",
                "attack": "SSH Brute Force",
                "ip": ip,
                "timestamp": now,
                "message": f"High-rate SSH authentication attempts from {ip}",
                "tips": "Inspect /var/log/auth.log and block the IP if malicious.",
                "status": "unresolved"
            }

            collection.insert_one(alert)
            last_alert_time[ip] = now

            print("🚨 ALERT STORED:", alert)

except KeyboardInterrupt:
    print("\nSSH monitoring stopped.")

finally:
    proc.terminate()
    client.close()
