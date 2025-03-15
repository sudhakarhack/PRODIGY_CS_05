from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    """Process captured network packets."""
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto  # Protocol number
        
        # Determine protocol type
        protocol = "Unknown"
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        
        # Extract payload data (if available)
        payload = ""
        if Raw in packet:
            payload = packet[Raw].load[:50]  # Limit output to 50 bytes
        
        print(f"[+] {protocol} Packet: {src_ip} → {dst_ip}")
        if payload:
            print(f"    Payload: {payload}")

# Start packet sniffing (Requires Administrator/root privileges)
print("🚀 Capturing packets... (Press CTRL+C to stop)")
sniff(filter="ip", prn=packet_callback, store=False)
