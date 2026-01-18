import subprocess
import csv
from collections import defaultdict, deque
from datetime import datetime, timezone

# ================= CONFIG ================= #

INTERFACE = "any"
TIME_WINDOW = 30            # seconds
MAC_THRESHOLD = 2           # MACs per IP
ALERT_COOLDOWN = 30         # seconds
ATTACK_TYPE = "ARP_SPOOFING"

CSV_FILE = "arp_spoofing_alerts.csv"

# ========================================= #

# DATA STRUCTURES
ip_mac_map = defaultdict(lambda: defaultdict(deque))
last_alert = {}

# CSV SETUP
with open(CSV_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp",
        "attack_type",
        "ip",
        "mac_count",
        "time_window",
        "severity",
        "message"
    ])

# TSHARK COMMAND
cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "arp.opcode == 2",
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

print("ARP Spoofing IDS started (CSV logging enabled)...")

# ================= MAIN LOOP ================= #

try:
    for line in proc.stdout:
        try:
            timestamp, ip, mac = line.strip().split()
            timestamp = float(timestamp)
        except ValueError:
            continue

        # Track MAC usage per IP
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

            if last_time and (now - last_time).total_seconds() < ALERT_COOLDOWN:
                continue

            alert = [
                now.isoformat(),
                ATTACK_TYPE,
                ip,
                mac_count,
                TIME_WINDOW,
                "High",
                "Possible ARP spoofing detected: IP mapped to multiple MAC addresses"
            ]

            # Write to CSV
            with open(CSV_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(alert)

            print("ALERT SAVED TO CSV:", alert)

            last_alert[ip] = now
            ip_mac_map[ip].clear()

except KeyboardInterrupt:
    print("\nStopping ARP Spoofing IDS...")

finally:
    proc.terminate()
    proc.wait()
    print("IDS shutdown complete")
