import sys
from scapy.all import rdpcap, IP, TCP, UDP

pcap_path = r"F:\projects\LogXPro\2026-01-29-njRAT-infection-with-MassLogger.pcap"
try:
    packets = rdpcap(pcap_path)
    print(f"Total packets: {len(packets)}")
    
    conns = set()
    for pkt in packets:
        if pkt.haslayer(IP):
            ip_dst = pkt[IP].dst
            port_dst = None
            proto = None
            if pkt.haslayer(TCP):
                port_dst = pkt[TCP].dport
                proto = "TCP"
            elif pkt.haslayer(UDP):
                port_dst = pkt[UDP].dport
                proto = "UDP"
            if port_dst:
                conns.add((ip_dst, port_dst, proto))
                
    print("\nUnique Destinations:")
    for ip, port, proto in sorted(conns):
        print(f"  {ip}:{port} ({proto})")
except Exception as e:
    print(f"Error reading PCAP: {e}")
