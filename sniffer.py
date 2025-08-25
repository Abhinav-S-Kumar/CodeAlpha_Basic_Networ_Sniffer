from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

        print(f"\n[+] Packet Captured")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        print(f"    Protocol: {protocol}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload: {payload[:50]}...")  # Show first 50 bytes

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
