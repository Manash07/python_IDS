# *** Every comment I have done is a self note for better understanding of the code. *** #

import subprocess
import os
from collections import deque
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

threshold = 100  # number of packets
time_window = 5  # seconds
interface = "any"  # network interface to use
MONGO_URI = os.getenv("MONGO_URI")  # MongoDB connection string from environment variable

#Connecting to MongoDB
try:
    client = MongoClient(MONGO_URI)
    print("Connected to MongoDB successfully.")

except:
    print("Unable to connected to the MongoDB.")
    exit(1)


database = client["check"] #Name of the database
collection = database['alerts'] #Name of Collection


# sliding window to store timestamps of ICMP packets

ip_record = {} #Empty dictionary where IP and timestamps will be stored

# Command to capture the ICMP packets using tshark

cmd = [

    "tshark", 
    "-i", interface, # for any interface
    "-Y", "icmp.type == 8",  # Filter for ICMP Echo Request packets
    "-T", 
    "fields",  # Output format: fields
    "-e", 
    "frame.time_epoch",  # Extract packet timestamp
    "-e",
    "ip.src"  # Extract source IP address
]


# Start the tshark process

proc = subprocess.Popen(cmd, stdout= subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


try:
    for line in proc.stdout:
        try:
            tst, ip = line.strip().split()
            tst = float(tst)
        except:
            continue

        if ip not in ip_record:
            ip_record[ip] = deque() #Making a queue for each new IP

        ip_record[ip].append(tst)
        
        while ip_record[ip] and ip_record[ip][0] < tst - time_window:
            ip_record[ip].popleft()  # Remove timestamps outside the sliding window
            print(ip_record) #Optional not required 

        if len(ip_record[ip]) >= threshold:
            count = len(ip_record[ip])
    
            alert = {
                "ip": ip,
                "timestamp": datetime.now(timezone.utc),
                "message": f"ICMP flood detected from {ip} with {len(ip_record[ip])} packets in {time_window} seconds."
            }
            collection.insert_one(alert)  # Insert alert into MongoDB
            print(alert)
            proc.terminate()  # Terminate tshark process after alert
            break


except KeyboardInterrupt:
    print("Stopping ICMP monitoring.")

finally:
    proc.wait()
