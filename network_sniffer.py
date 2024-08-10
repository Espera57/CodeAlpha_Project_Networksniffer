from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP

def packet_callback(packet):
    # Determine the type of packet and extract relevant information
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"
            sport = ""
            dport = ""
        else:
            proto = "Other"
            sport = ""
            dport = ""

        print(f"Protocol: {proto} | Source IP: {ip_src}:{sport} -> Destination IP: {ip_dst}:{dport}")
    
    elif ARP in packet:
        proto = "ARP"
        print(f"Protocol: {proto} | Source MAC: {packet[ARP].hwsrc} -> Destination MAC: {packet[ARP].hwdst}")

# Start sniffing with a filter for IP packets and ARP
print("Starting the packet capture...")
sniff(prn=packet_callback, filter="ip or arp", store=0)
