from scapy.all import IP, TCP, ICMP

def decode_packet(packet):
    """Protocol-agnostic decoder for structured data extraction."""
    if not packet.haslayer(IP):
        return None

    data = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "proto": packet[IP].proto
    }

    if packet.haslayer(TCP):
        data["type"] = "TCP"
        data["dst_port"] = packet[TCP].dport
    elif packet.haslayer(ICMP):
        data["type"] = "ICMP"
        data["icmp_type"] = packet[ICMP].type
    
    return data
 