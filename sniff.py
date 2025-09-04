"""
sniff.py - Network Packet Sniffer

A Python script to capture and analyze network packets using Scapy.
- Displays source/destination IPs, ports, protocol, and payload in real-time.
- Saves captured packets into TXT, CSV, JSON, and PCAP files.
- Helps understand how data flows in networks and the basics of protocols.

Usage:
    python sniff.py   (Run with Administrator / sudo privileges)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from datetime import datetime
import json
import csv
import signal
import sys
import string

captured_packets = []  # store packet summaries for saving
raw_packets = []       # store raw packets for .pcap saving


def clean_payload(raw_data, length=100):
    """Convert raw bytes into a human-readable string (printable only)."""
    try:
        text = raw_data.decode("utf-8", errors="ignore")
    except:
        text = str(raw_data)

    printable = ''.join(ch if ch in string.printable else '.' for ch in text)
    return printable[:length]


def packet_callback(packet):
    """Callback for each captured packet."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pkt_data = {
        "timestamp": timestamp,
        "src": None,
        "dst": None,
        "protocol": None,
        "sport": None,
        "dport": None,
        "payload": None
    }

    # Extract IP info
    if IP in packet:
        pkt_data["src"] = packet[IP].src
        pkt_data["dst"] = packet[IP].dst
        proto = packet[IP].proto
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        pkt_data["protocol"] = proto_map.get(proto, str(proto))

        # Transport layer details
        if TCP in packet:
            pkt_data["sport"] = packet[TCP].sport
            pkt_data["dport"] = packet[TCP].dport
        elif UDP in packet:
            pkt_data["sport"] = packet[UDP].sport
            pkt_data["dport"] = packet[UDP].dport
        elif ICMP in packet:
            pkt_data["protocol"] = "ICMP"

        # Application layer payload
        if Raw in packet:
            pkt_data["payload"] = clean_payload(bytes(packet[Raw].load))

        # Print live info
        print(f"\n[{timestamp}] {pkt_data['src']} --> {pkt_data['dst']} | Protocol: {pkt_data['protocol']}")
        if pkt_data["sport"] and pkt_data["dport"]:
            print(f"   Ports: {pkt_data['sport']} -> {pkt_data['dport']}")
        if pkt_data["payload"]:
            print(f"   Payload: {pkt_data['payload']}")

    captured_packets.append(pkt_data)
    raw_packets.append(packet)


def save_results():
    """Save captured packets into TXT, CSV, JSON, and PCAP files."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    txt_path = f"captured_{timestamp}.txt"
    csv_path = f"captured_{timestamp}.csv"
    json_path = f"captured_{timestamp}.json"
    pcap_path = f"captured_{timestamp}.pcap"

    # Save TXT
    with open(txt_path, "w", encoding="utf-8", errors="ignore") as f:
        for pkt in captured_packets:
            f.write(f"[{pkt['timestamp']}] {pkt['src']} --> {pkt['dst']} | Protocol: {pkt['protocol']}\n")
            if pkt['sport'] and pkt['dport']:
                f.write(f"   Ports: {pkt['sport']} -> {pkt['dport']}\n")
            if pkt['payload']:
                f.write(f"   Payload: {pkt['payload']}\n")
            f.write("\n")

    # Save CSV
    with open(csv_path, "w", newline="", encoding="utf-8", errors="ignore") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src", "dst", "protocol", "sport", "dport", "payload"])
        writer.writeheader()
        writer.writerows(captured_packets)

    # Save JSON
    with open(json_path, "w", encoding="utf-8", errors="ignore") as f:
        json.dump(captured_packets, f, indent=4, ensure_ascii=False)

    # Save PCAP
    wrpcap(pcap_path, raw_packets)

    print(f"\n[+] Results saved as:\n  TXT  -> {txt_path}\n  CSV  -> {csv_path}\n  JSON -> {json_path}\n  PCAP -> {pcap_path}")


def signal_handler(sig, frame):
    """Handle Ctrl+C (stop capture and save results)."""
    print("\n[!] Ctrl+C detected, stopping capture...")
    save_results()
    sys.exit(0)


def start_sniffing():
    """Start packet sniffing."""
    print("[*] Starting packet capture... Press Ctrl+C to stop.\n")
    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_sniffing()
