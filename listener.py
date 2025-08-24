from scapy.all import sniff, TCP, Raw

SERVER_PORT = 12346  # jo port aapka server use kar raha hai

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        print(f"[SPY] Raw Encrypted Data: {packet[Raw].load}")

print(f"[SPY] Listening for TCP traffic on port {SERVER_PORT} ...")
sniff(filter=f"tcp port {SERVER_PORT}", prn=packet_callback, store=0, iface="lo0")
