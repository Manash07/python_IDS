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

INTERFACE = "any"
TIME_WINDOW = 30          # seconds
MAC_THRESHOLD = 2         # different MACs for same IP
ALERT_COOLDOWN = 30       # seconds (avoid alert spam)

# MONGODB

client = MongoClient(MONGO_URI)
db = client["alert_db"]
collection = db["alerts"]

# DATA STRUCTURES

ip_mac_map = defaultdict(lambda: defaultdict(deque))
last_alert = {}

# TSHARK COMMAND

cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "arp.opcode == 2",          # ARP Reply
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "arp.src.proto_ipv4",
    "-e", "arp.src.hw_mac"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("ARP Spoofing Detection Started...")

# MAIN LOOP

try:
    for line in proc.stdout:
        try:
            timestamp, ip, mac = line.strip().split()
            timestamp = float(timestamp)
        except ValueError:
            continue

        # Store MAC usage per IP
        ip_mac_map[ip][mac].append(timestamp)

        # Cleanup old entries (sliding window)
        for m in list(ip_mac_map[ip].keys()):
            while ip_mac_map[ip][m] and ip_mac_map[ip][m][0] < timestamp - TIME_WINDOW:
                ip_mac_map[ip][m].popleft()

            if not ip_mac_map[ip][m]:
                del ip_mac_map[ip][m]

        mac_count = len(ip_mac_map[ip])
        print(f"ARP Reply: {ip} → MACs seen = {mac_count}")

        # DETECTION

        if mac_count >= MAC_THRESHOLD:
            now = datetime.now(timezone.utc)

            # Cooldown check
            if ip in last_alert and (now - last_alert[ip]).total_seconds() < ALERT_COOLDOWN:
                continue

            alert = {
                "type": "alert",
                "attack": "ARP Spoofing",
                "ip": ip,
                # "mac_addresses": list(ip_mac_map[ip].keys()),
                "timestamp": now,
                "message": f"ARP spoofing suspected: {ip} mapped to multiple MAC addresses",
                "tips": "Verify network devices and consider using static ARP entries.",
                "status": "unresolved"
            }

            # Store alert in MongoDB
            collection.insert_one(alert)

            print("ALERT STORED IN DATABASE:", alert)

            last_alert[ip] = now

except KeyboardInterrupt:
    print("\n Stopping ARP Spoofing Detection...")

finally:
    proc.terminate()
    proc.wait()
    client.close()
    print("Detector shutdown complete")
