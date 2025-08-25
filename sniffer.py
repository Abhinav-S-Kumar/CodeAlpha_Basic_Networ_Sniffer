from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocol mapping
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

        print(f"\n[+] Packet Captured")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        print(f"    Protocol: {protocol}")

        # Show payload if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                print(f"    Payload: {payload[:50]}...")  # First 50 bytes
            except Exception as e:
                print(f"    Payload: (unreadable) | Error: {e}")

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
