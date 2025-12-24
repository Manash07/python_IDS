import subprocess
from collections import defaultdict

# Threshold for brute-force alert
threshold = 5  
interface = "any"
# Count unsuccessful SSH attempts per source IP
attempt_count = defaultdict(int)

# Run tshark to capture SSH packets in real-time
# tcp.flags.syn == 1 and tcp.flags.ack == 0 means connection attempt
tshark_cmd = [
    "tshark",
    "-l", "-i", interface,
    "-Y", "tcp.dstport == 22 and tcp.flags.syn == 1 and tcp.flags.ack == 0",
    "-T", "fields",
    "-e", "ip.src"
]

print("🔍 Monitoring SSH traffic... Press Ctrl+C to stop.\n")

process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

try:
    for raw_line in iter(process.stdout.readline, b""):
        line = raw_line.decode().strip()
        if not line:
            continue
        
        src_ip = line
        attempt_count[src_ip] += 1

        print(f"[+] SSH attempt detected from {src_ip}. Count = {attempt_count[src_ip]}")

        if attempt_count[src_ip] >= THRESHOLD:
            print("\n🚨 ALERT! SSH Brute Force Attempt Detected!")
            print(f"Source IP: {src_ip}")
            print(f"Attempts: {attempt_count[src_ip]}")
            print("Action recommended: Block IP using firewall (ufw/iptables)\n")
            attempt_count[src_ip] = 0
            
except KeyboardInterrupt:
    print("\nMonitoring stopped.")
    process.terminate()

