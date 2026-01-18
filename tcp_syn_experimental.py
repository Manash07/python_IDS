import subprocess
import csv
from collections import deque
from datetime import datetime, timezone

# ================= CONFIG ================= #

INTERFACE = "any"
TIME_WINDOW = 1              # seconds
THRESHOLD = 500               # SYN packets per IP
ATTACK_TYPE = "TCP_SYN_FLOOD"

CSV_FILE = "tcp_syn_dataset.csv"

# ========================================= #

# STATE TRACKING
ip_record = {}
attack_state = {}

# ================= CSV SETUP ================= #

with open(CSV_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp",
        "src_ip",
        "dst_ip",
        "ip_len",
        "ttl",
        "src_port",
        "dst_port",
        "tcp_seq",
        "packet_count",
        "label"
    ])

# ================= TSHARK ================= #

cmd = [
    "tshark",
    "-n",
    "-l",
    "-i", INTERFACE,
    "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    "-T", "fields",
    "-E", "separator=,",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "ip.len",
    "-e", "ip.ttl",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "tcp.seq"
]

proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1
)

print("TCP SYN Flood IDS started (stateful CSV logging)...")

# ================= MAIN LOOP ================= #

try:
    for line in proc.stdout:
        fields = line.strip().split(",")

        if len(fields) < 8:
            continue

        (
            frame_time,
            src_ip,
            dst_ip,
            ip_len,
            ttl,
            src_port,
            dst_port,
            tcp_seq
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

        # =========================
        # STATEFUL RATE-BASED LABELING
        # =========================

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
                ip_len,
                ttl,
                src_port,
                dst_port,
                tcp_seq,
                packet_count,
                label
            ])

        print(f"[{label}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | count={packet_count}")

except KeyboardInterrupt:
    print("\nStopping TCP SYN IDS...")

finally:
    proc.terminate()
    proc.wait()
    print("IDS shutdown complete")
