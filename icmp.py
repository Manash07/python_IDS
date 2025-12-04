# *** Every comment I have done is a self note for better understanding of the code. *** #

import subprocess
import os
from collections import deque
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

threshold = 100  # number of packets
window = 5  # seconds
interface = "any"  # network interface to use
MONGO_URI = os.getenv("MONGO_URI")  # MongoDB connection string from environment variable

#Connecting to MongoDB
try:
    client = MongoClient(MONGO_URI)
    print("Connected to MongoDB successfully.")

except:
    print("Unable to connected to the MongoDB.")
    exit(1)


db = client["check"] #Name of the database
collection = db['alerts'] #Name of Collection


# sliding window to store timestamps of ICMP packets

ip_windows = {} #Empty dictionary where IP and timestamps will be stored

# command to capture the ICMP packets using tshark

cmd = [

    "tshark", 
    "-i", interface, # for any interface
    "-Y", "icmp.type == 8",  # Filter for ICMP Echo Request packets
    "-T", 
    "fields",  # Output format: fields
    "-e", 
    "frame.time_epoch",  # Extract packet timestamp
    "e",
    "ip.src"  # Extract source IP address
]


# Start the tshark process

proc = subprocess.Popen(cmd, stdout= subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


try:
    for line in proc.stdout:
        try:
            ts, ip = line.strip().split()
            ts = float(ts)
        except:
            continue

        if ip not in ip_windows:
            ip_windows[ip] = deque() #Making a queue for each new IP

            ip_windows[ip].append(ts)



except KeyboardInterrupt:
    print("Stopping ICMP monitoring.")

finally:
    proc.wait
