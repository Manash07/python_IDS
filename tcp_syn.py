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
THRESHOLD = 500          # SYN packets
TIME_WINDOW = 10        # seconds
ALERT_COOLDOWN = 60     # seconds
INTERFACE = "any"

# MongoDB
client = MongoClient(MONGO_URI)
db = client["alert_db"]
collection = db["alerts"]

# Tracking
syn_packets = defaultdict(deque)
last_alert = {}

# TSHARK
cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
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

print("TCP SYN Flood Detection Started...")

# MAIN LOOP
try:
    for line in proc.stdout:
        try:
            timestamp, ip = line.strip().split()
            timestamp = float(timestamp)
        except ValueError:
            continue

        syn_packets[ip].append(timestamp)

        # Sliding window cleanup
        while syn_packets[ip] and syn_packets[ip][0] < timestamp - TIME_WINDOW:
            syn_packets[ip].popleft()

        count = len(syn_packets[ip])
        print(f"SYN packets from {ip} | count={count}")

        if count >= THRESHOLD:
            now = datetime.now(timezone.utc)

            # Cooldown check
            if ip in last_alert:
                if (now - last_alert[ip]).total_seconds() < ALERT_COOLDOWN:
                    continue

            alert = {
                "type": "alert",
                "attack": "TCP SYN Flood",
                "ip": ip,
                "timestamp": now,
                "message": "High rate of TCP SYN packets detected "
                "(possible SYN flood attack)",
                "status": "unresolved"
            }

            collection.insert_one(alert)
            last_alert[ip] = now

            print("ALERT STORED:", alert)

except KeyboardInterrupt:
    print("\nStopping TCP SYN Flood Detection...")

finally:
    proc.terminate()
    proc.wait()
    client.close()
