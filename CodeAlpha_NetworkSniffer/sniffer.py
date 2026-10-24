"""
CodeAlpha Cyber Security Internship - Task 1
Basic Network Sniffer using Python + Scapy

Run as Administrator (Windows) or with sudo (Linux/Mac).
Only sniff traffic on your own network.
"""
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def process_packet(packet):
    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")
    sport = dport = "-"

    if TCP in packet:
        proto = "TCP"
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        proto = "UDP"
        sport, dport = packet[UDP].sport, packet[UDP].dport
    elif ICMP in packet:
        proto = "ICMP"
    else:
        proto = str(packet[IP].proto)

    print("=" * 55)
    print(f"Time           : {timestamp}")
    print(f"Source IP      : {src}:{sport}")
    print(f"Destination IP : {dst}:{dport}")
    print(f"Protocol       : {proto}")

    if Raw in packet:
        print(f"Payload        : {bytes(packet[Raw].load)[:50]}")
    else:
        print("Payload        : (empty)")


if __name__ == "__main__":
    print("Sniffing started... (capturing 20 packets, Ctrl+C to stop)")
    sniff(prn=process_packet, count=20, store=False)
    print("Done.")
