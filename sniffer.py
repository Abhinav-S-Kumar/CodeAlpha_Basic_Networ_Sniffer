from scapy.all import sniff

# Function to handle each packet
def packet_handler(packet):
    print(packet.summary())

# Capture only 5 packets (for demo)
print("Starting dummy packet capture (Press CTRL+C to stop)...")
sniff(count=5, prn=packet_handler)
