import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone

# CONFIG
INTERFACE = "any"
TIME_WINDOW = 30        # seconds
MAC_THRESHOLD = 2       # different MACs for same IP

# DATA STRUCTURES 
ip_mac_map = defaultdict(lambda: defaultdict(deque))
last_alert = {}

# TSHARK COMMAND
cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "arp.opcode == 2",          # ARP Reply (poisoning happens via replies)
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

        # Cleanup old entries
        for m in list(ip_mac_map[ip].keys()):
            while ip_mac_map[ip][m] and ip_mac_map[ip][m][0] < timestamp - TIME_WINDOW:
                ip_mac_map[ip][m].popleft()

            if not ip_mac_map[ip][m]:
                del ip_mac_map[ip][m]

        mac_count = len(ip_mac_map[ip])
        print(f"ARP Reply: {ip} → MACs seen = {mac_count}")

        # Detection condition
        if mac_count >= MAC_THRESHOLD:
            now = datetime.now(timezone.utc)

            # Prevent alert spam
            if ip in last_alert and (now - last_alert[ip]).seconds < TIME_WINDOW:
                continue

            alert = {
                "attack": "ARP Spoofing",
                "ip": ip,
                "mac_addresses": list(ip_mac_map[ip].keys()),
                "timestamp": now.isoformat(),
                "severity": "High",
                "message": f"ARP spoofing suspected: {ip} mapped to multiple MAC addresses"
            }

            print("ALERT:", alert)
            last_alert[ip] = now

except KeyboardInterrupt:
    print("\nStopping ARP Spoofing Detection...")

finally:
    proc.terminate()
    proc.wait()
