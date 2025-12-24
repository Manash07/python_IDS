# *** Every comment I have done is a self note for better understanding of the code. *** #
import subprocess
from collections import deque
from datetime import datetime, timezone
from pymongo import MongoClient
import os
from dotenv import load_dotenv



load_dotenv(dotenv_path="/home/manash/Desktop/networkids/python/.env", override=True)

# ------------------ Configuration ------------------ #

threshold = 100
time_window = 5
interface = "any"
MONGO_URI = os.getenv("MONGO_URI")

# ------------------ MongoDB ------------------ #
client = MongoClient(MONGO_URI)
database = client["alert_db"]
collection = database["icmp_alerts"]

# ------------------ ICMP Detection ------------------ #
ip_record = {}        # timestamps per IP
last_alert_time = {}  # cooldown per IP
ALERT_COOLDOWN = 30   # seconds

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

print("ICMP monitoring started...")

try:
    for line in proc.stdout:
        try:
            tst, ip = line.strip().split()
            tst = float(tst)
        except ValueError:
            continue

        if ip not in ip_record:
            ip_record[ip] = deque()

        ip_record[ip].append(tst)

        # Sliding window cleanup
        while ip_record[ip] and ip_record[ip][0] < tst - time_window:
            ip_record[ip].popleft()

        print(f"ICMP from {ip} | count={len(ip_record[ip])}")

        # Detection
        if len(ip_record[ip]) >= threshold:
            now = datetime.now(timezone.utc)

            # Cooldown check
            if ip in last_alert_time:
                elapsed = (now - last_alert_time[ip]).total_seconds()
                if elapsed < ALERT_COOLDOWN:
                    continue

            alert = {
                "type": "alert",
                "ip": ip,
                "timestamp": now,
                "message": f"Possible ICMP flood detected from {ip}",
                "tips": "Investigate source IP and apply firewall rules if needed."
            }

            collection.insert_one(alert)
            last_alert_time[ip] = now

            print("🚨 ALERT:", alert)

except KeyboardInterrupt:
    print("\nICMP monitoring stopped by user.")

finally:
    proc.terminate()
    proc.wait()
    client.close()

# *** Every comment I have done is a self note for better understanding of the code. *** #