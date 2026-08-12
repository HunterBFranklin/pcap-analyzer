# =============================================================================
# pcap-analyzer — dns_anomaly.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Aug. 7, 2026
# Modified    : Aug. 11, 2026
# =============================================================================

from scapy.all import *
from math import log2
from collections import Counter

def extract_dns_queries(packets):

    """
    Extracts all Domain Name System (DNS) queries out of a raw packet list
    and returns them in a cleaner form. Forms a Python object, rather than having
    raw Scapy data.
    """

    queries = []

    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried_domain = packet[DNSQR].qname.decode().rstrip('.')
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                queries.append({
                    'src_ip': src_ip, 
                    'queried_domain': queried_domain})

    return queries


def get_tld(domain: str):

    """
    Extracts the Top Level Domain (TLD) from a domain string and returns it.
    """

    domain_split = domain.split(".")
    tld = domain_split[-1]
    return tld


def get_sld(domain: str):

    """
    Extracts the Second Level Domain (SLD) from a domain string and returns it.
    """

    domain_split = domain.split(".")
    sld = domain_split[-2]
    return sld


def shannon_entropy(s: str):

    """
    Computes the Shannon entropy of a string in bits. Higher values indicate more
    randomness, which can be used to detect Domain Generation Algorithm (DGA)
    activity.
    """

    if s is None:
        return 0

    string_length = len(s)
    string_count = Counter(s)
    entropy = 0

    for value in string_count.values():
        p_c = value / string_length
        entropy += p_c * log2(p_c)

    return -entropy


def is_rare_tld(tld: str, blocklist: set):

    """
    
    """

    pass


def analyze_dns(packets, tld_blocklist: set, entropy_threshold: float):

    """
    
    """

    pass