import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Environment variables

load_dotenv(dotenv_path="/home/manash/Desktop/networkids/python/.env", override=True)
MONGO_URI = os.getenv("MONGO_URI")

# Configuration 

threshold = 100        # ICMP packets in window
time_window = 5        # seconds
interface = "any"
ALERT_COOLDOWN = 60    # seconds

# MongoDB
client = MongoClient(MONGO_URI)
db = client["alert_db"]
collection = db["alerts"]

# ICMP Tracking
ip_packets = defaultdict(deque)
last_alert_time = {}

# ICMP Echo Request filter
cmd = [
    "tshark",
    "-i", interface,
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

print("ICMP Ping Flood monitoring started..")

try:
    for line in proc.stdout:
        try:
            timestamp, ip = line.strip().split()
            timestamp = float(timestamp)
        except ValueError:
            continue

        ip_packets[ip].append(timestamp)

        # Sliding window cleanup
        while ip_packets[ip] and ip_packets[ip][0] < timestamp - time_window:
            ip_packets[ip].popleft()

        count = len(ip_packets[ip])
        print(f"ICMP packets from {ip} | count={count}")

        if count >= threshold:
            now = datetime.now(timezone.utc)

            # Cooldown check
            if ip in last_alert_time:
                if (now - last_alert_time[ip]).total_seconds() < ALERT_COOLDOWN:
                    continue

            alert = {
                "type": "alert",
                "attack": "ICMP Ping Flood",
                "ip": ip,
                "packet_count": count,
                "time_window": time_window,
                "timestamp": now,
                "message": f"High-rate ICMP echo requests detected from {ip}",
                "tips": "Check firewall rules and consider rate limiting ICMP.",
                "status": "unresolved"
            }

            collection.insert_one(alert)
            last_alert_time[ip] = now

            print("ALERT STORED:", alert)

except KeyboardInterrupt:
    print("ICMP monitoring stopped by user.")

finally:
    proc.terminate()
    proc.wait()
    client.close()