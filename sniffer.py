import time
import random

# Some fake IPs & protocols for demo
fake_ips = ["10.0.0.5", "192.168.10.25", "172.16.0.11", "203.0.113.45", "198.51.100.7"]
protocols = ["TCP", "UDP", "ICMP", "Protocol: 2"]

def generate_fake_packet():
    src = random.choice(fake_ips)
    dst = random.choice(fake_ips)
    while dst == src:
        dst = random.choice(fake_ips)

    proto = random.choice(protocols)
    payload = "b'" + "\\x" + "\\x".join([f"{random.randint(0,255):02x}" for _ in range(12)]) + "...'"

    print("\n[+] Packet Captured")
    print(f"    Source IP: {src}")
    print(f"    Destination IP: {dst}")
    print(f"    Protocol: {proto}")
    if proto in ["TCP", "UDP", "Protocol: 2"]:
        print(f"    Payload: {payload}")

# Main loop
print("Starting dummy packet sniffer... Press Ctrl+C to stop.\n")
try:
    while True:
        generate_fake_packet()
        time.sleep(2)  # wait 2 seconds between packets
except KeyboardInterrupt:
    print("\nStopped dummy sniffer.")
