from scapy.all import sniff, IP, TCP, UDP

# Packet handler function
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

        print("="*50)

# Function to start sniffing
def start_sniffing(packet_count=10):
    sniff(prn=packet_handler, count=packet_count)

# Run the sniffer
if __name__ == "__main__":
    start_sniffing(packet_count=20)
