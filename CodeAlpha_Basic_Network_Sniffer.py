from scapy.all import sniff, IP, TCP

def packet_handler(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")
        
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")

if __name__ == "__main__":
    print("Starting network sniffer...")
    sniff(prn=packet_handler, count=10000)  # Change 'count' for more packets or remove it to sniff indefinitely



