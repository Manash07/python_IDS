import subprocess
import csv
import os
from collections import deque
from datetime import datetime, timezone

# =========================
# CONFIGURATION
# =========================

THRESHOLD = 20          # SSH packets per TIME_WINDOW
TIME_WINDOW = 10        # seconds
INTERFACE = "any"

ATTACK_TYPE = "SSH_BRUTE_FORCE"
CSV_FILE = "ssh_traffic_log.csv"


# DATA STRUCTURES


ip_record = {}          # Sliding window timestamps per IP
attack_state = {}       # IP -> True / False


# CSV INITIALIZATION


if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "tcp_flags",
            "packet_count",
            "label"
        ])


# TSHARK COMMAND


cmd = [
    "tshark",
    "-i", INTERFACE,
    "-Y", "tcp.port == 22",
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "tcp.flags",
    "-E", "separator=,"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("[*] SSH traffic capture started (CSV only)...")

# MAIN LOOP

try:
    for line in proc.stdout:
        fields = line.strip().split(",")

        if len(fields) < 6:
            continue

        (
            frame_time,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags
        ) = fields

        try:
            timestamp = float(frame_time)
        except ValueError:
            continue

        # Initialize sliding window
        if src_ip not in ip_record:
            ip_record[src_ip] = deque()

        ip_record[src_ip].append(timestamp)

        # Sliding window cleanup
        while ip_record[src_ip] and ip_record[src_ip][0] < timestamp - TIME_WINDOW:
            ip_record[src_ip].popleft()

        packet_count = len(ip_record[src_ip])

        # STATEFUL RATE-BASED LABELING
      

        if packet_count >= THRESHOLD:
            attack_state[src_ip] = True
        else:
            attack_state[src_ip] = False

        label = ATTACK_TYPE if attack_state[src_ip] else "NORMAL"

        # WRITE TO CSV

        with open(CSV_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now(timezone.utc).isoformat(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_flags,
                packet_count,
                label
            ])

        print(f"[{label}] {src_ip} → {dst_ip} | count={packet_count}")

except KeyboardInterrupt:
    print("\n[*] Stopping SSH capture...")

finally:
    proc.terminate()
    print("[*] Capture stopped, CSV saved.")
