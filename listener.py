from scapy.all import sniff, TCP, Raw, IP

SERVER_IP = "192.168.55.165"   # आपका server ip
SERVER_PORT = 12346            # आपका server port

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)

        if tcp_layer.dport == SERVER_PORT or tcp_layer.sport == SERVER_PORT:
            print(f"\n[PACKET] {ip_layer.src} -> {ip_layer.dst}  |  {len(packet[Raw].load)} bytes")
            print(f"Raw Data (encrypted): {packet[Raw].load[:100]}")  # सिर्फ first 100 bytes दिखाएंगे

print(f"[INFO] Listening on TCP port {SERVER_PORT} ... (Ctrl+C to stop)")
sniff(filter=f"tcp port {SERVER_PORT}", prn=packet_callback, store=False)

# run command  =>  sudo tcpdump -i any tcp port 12346 -A