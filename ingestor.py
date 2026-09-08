# =============================================================================
# pcap-analyzer — ingestor.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Aug. 7, 2026
# Modified    : Sep. 7, 2026
# =============================================================================

from scapy.all import *
from collections import defaultdict
from datetime import datetime, timezone

def read_pcap(filepath: str):

    """
    Reads a .pcap file from the disk and returns raw packets.
    """

    # Scapy function to read a .pcap and return packets.
    return rdpcap(filepath)


def start_live_capture(iface: str, packet_count: int, bpf_filter: str):

    """
    Captures live packets from a network using scapy sniff() and returns
    a captured packet list.
    """

    # Sniffs the network interface, Berkley filter, and capture count.
    return sniff(iface=iface, filter=bpf_filter, count=packet_count)
    

def extract_flows(packets: list):

    """
    Iterates through the captured packets and calls parse_packet() to
    group the results into dictionary keyed five-tuple.
    """

    flows_dict = defaultdict(list)
    for packet in packets:
        result = parse_packet(packet)
        if result is None:
            continue
        five_tuple = (result['src_ip'], result['dst_ip'], result['src_port'], result['dst_port'],
                      result['protocol'])
        flows_dict[five_tuple].append(result['timestamp'])

    return flows_dict


def parse_packet(packet):

    """
    Uses scapy haslayer() to guard and extracts the source IP, dest IP, source port,
    dest port, protocol, and timestamp to form a five-tuple dictionary in extract_flows().
    """

    if not packet.haslayer(IP): # If the IP layer isn't present, returns None.
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Determines the packet protocol and sets values for five-tuple.
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
    else:
        src_port = None
        dst_port = None
        protocol = None

    # Output for five-tuple.
    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'timestamp': float(packet.time)
    }