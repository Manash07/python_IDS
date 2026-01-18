import subprocess
import socketio
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
TIME_WINDOW = 30           # seconds
MAC_THRESHOLD = 2          # different MACs for same IP
ALERT_COOLDOWN = 30        # seconds
ATTACK_TYPE = "ARP_SPOOFING"

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
    "-Y", "arp.opcode == 2",       # ARP Reply
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

print("Live ARP Spoofing IDS started...")

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

        # Sliding window cleanup
        for m in list(ip_mac_map[ip].keys()):
            while ip_mac_map[ip][m] and ip_mac_map[ip][m][0] < timestamp - TIME_WINDOW:
                ip_mac_map[ip][m].popleft()

            if not ip_mac_map[ip][m]:
                del ip_mac_map[ip][m]

        mac_count = len(ip_mac_map[ip])
        print(f"ARP Reply from {ip} | MACs seen = {mac_count}")

        # DETECTION
        if mac_count >= MAC_THRESHOLD:
            now = datetime.now(timezone.utc)
            last_time = last_alert.get(ip)

            # Cooldown check
            if last_time and (now - last_time).total_seconds() < ALERT_COOLDOWN:
                continue

            alert = {
                "attack_type": ATTACK_TYPE,
                "ip": ip,
                "mac_count": mac_count,
                "time_window": TIME_WINDOW,
                "severity": "High",
                "timestamp": now.isoformat(),
                "message": "Possible ARP spoofing detected: IP mapped to multiple MAC addresses",
                "status": "unresolved"
            }

            # Store alert in MongoDB
            collection.insert_one(alert)

            # Emit live alert to backend
            sio.emit("live_alert", alert)

            print("LIVE ALERT SENT & STORED:", alert)

            last_alert[ip] = now
            ip_mac_map[ip].clear()

except KeyboardInterrupt:
    print("\nStopping ARP Spoofing IDS...")

finally:
    proc.terminate()
    proc.wait()
    client.close()
    sio.disconnect()
    print("IDS shutdown complete")
