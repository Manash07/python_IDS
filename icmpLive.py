import subprocess
import socketio
import os
from collections import deque
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv(dotenv_path="/home/manash/Desktop/networkids/python/.env", override=True) # Load environment variables from .env file
MONGO_URI = os.getenv("MONGO_URI") # MongoDB connection string


BACKEND_SOCKET_URL = "http://localhost:5001" # Backend Socket.IO server URL

# ================= SOCKET.IO CLIENT ================= #

# This block of code establishes a Socket.IO client connection to a backend server.
# It also defines event handlers for connection and disconnection events, printing messages to the console when these events occur. 
# If the connection attempt fails, it catches the exception, prints an error message, and exits the program.

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

# ========================================================== #

# ================= MONGODB CONFIG ================= #

client = MongoClient(MONGO_URI)
db = client["alert_db"]
heuristic_collection = db["heuristics"]
alert_collection = db["alerts"]

def load_heuristic():
    # Fetch heuristic config from MongoDB #
    config = heuristic_collection.find_one({"_id": "icmp_heuristic"})
    if not config:
        print("[!] Heuristic config not found, using defaults")
        return {
            "interface": "any",
            "time_window": 5,
            "threshold": 100,
            "cooldown": 10
        }
    return {
        "interface": config.get("interface", "any"),
        "time_window": config.get("time_window", 5),
        "threshold": config.get("threshold", 100),
        "cooldown": config.get("cooldown", 10)
    }

# ========================================================== #

# ================= LOAD HEURISTIC ================= #


heuristic = load_heuristic() # Load heuristic configuration from MongoDB
INTERFACE = heuristic["interface"]
TIME_WINDOW = heuristic["time_window"]
THRESHOLD = heuristic["threshold"]
COOLDOWN = heuristic["cooldown"]

print(f"[*] Using heuristic: Interface={INTERFACE}, Time Window={TIME_WINDOW}, Threshold={THRESHOLD}, Cooldown={COOLDOWN}")

###############################################################


# ================= DATA STRUCTURES ================= #
ip_record = {}      # Dictionary to capture sliding window timestamps per IP
last_emitted = {}   # Dictionary for cooldown tracker per IP

# ================= TSHARK COMMAND ================= #

cmd = [
    "tshark",
    "-i", INTERFACE, # Network interface to capture packets from
    "-Y", "icmp.type == 8",   # ICMP echo request
    "-T", "fields", # Output format: fields
    "-e", "frame.time_epoch", # Epoch timestamp of the frame
    "-e", "ip.src" # Source IP address
]

proc = subprocess.Popen(  # Runs the command in a subprocess, allowing Python to interact with it in real time
    cmd, # Start tshark subprocess with specified command
    stdout=subprocess.PIPE, # Capture output of tshark
    stderr=subprocess.DEVNULL, # Ignore standard error
    text=True # Output as text
)

print("Live ICMP IDS started...")

#######################################################

# ================= MAIN LOOP =================
try:
    for line in proc.stdout:   #Reads line from the tshark output
        try:
            timestamp, ip = line.strip().split() # Parse timestamp and source IP from tshark output like this:
            #timestamp = '1705259123.456', ip = '192.168.0.5'

            timestamp = float(timestamp) #converts string to a float number because it includes decimal value
        except ValueError:
            continue

        # Initialize queue for new IP #

        # --> This block of code adds new ip into the deque. If the ip exists, it appends the timestamp in deque. #
        if ip not in ip_record:
            ip_record[ip] = deque()

        ip_record[ip].append(timestamp)

        #################################################

        ############################################

        # Sliding window cleanup #

        #This block of code removes timestamps from the deque that are older than the defined time window.    

        while ip_record[ip] and ip_record[ip][0] < timestamp - TIME_WINDOW:
            ip_record[ip].popleft()

        packet_count = len(ip_record[ip]) # Count packets in the current time window
        print(f"ICMP from {ip} | count={packet_count}")

        ####################################################

        # ================= DETECTION ================= #

        if packet_count >= THRESHOLD:
            now = datetime.now(timezone.utc)
            last_time = last_emitted.get(ip)

            if not last_time or (now - last_time).total_seconds() >= COOLDOWN:
                alert = {
                    "attack_type": "ICMP PING FLOOD",
                    "ip": ip,
                    "packet_count": packet_count,
                    "time_window": TIME_WINDOW,
                    "severity": "High",
                    "timestamp": now.isoformat(),
                    "message": "Possible ICMP overflood attack. Please take immediate action",
                    "status": "unresolved"
                }

                # Emit live alert to backend
                sio.emit("live_alert", alert)

                print("LIVE ALERT SENT", alert)

                last_emitted[ip] = now # Update last emitted time
                # ip_record[ip].clear()   # optional: I have keep it for continuous monitoring


except KeyboardInterrupt:
    print("Stopping Live ICMP IDS...")

finally:
    proc.terminate()
    proc.wait()
    client.close()
    sio.disconnect()
    print("IDS shutdown complete")

