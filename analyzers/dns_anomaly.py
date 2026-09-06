# =============================================================================
# pcap-analyzer — dns_anomaly.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Aug. 7, 2026
# Modified    : Aug. 11, 2026
# =============================================================================

from scapy.all import *
from math import log2
from collections import Counter

SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'cc', 'su', 'pw', 'ws', 'club', 'online', 'site', 'live'}

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
    Returns True if the Top-level Domain (TLD) is a member of a suspicious TLD
    blocklist.
    """

    return tld in blocklist


def analyze_dns(packets, tld_blocklist: set, entropy_threshold: float):

    """
    Calls extract_dns_queries, scores each domain with shannon_entropy and is_rare_tld,
    and returns alert records for flagged queries. 
    """

    alerts = []
    raw_packets = extract_dns_queries(packets)

    for packet in raw_packets:
        tld = get_tld(packet['queried_domain'])
        sld = get_sld(packet['queried_domain'])
        entropy = shannon_entropy(sld)
        rare_tld = is_rare_tld(tld, SUSPICIOUS_TLDS)

        if entropy > entropy_threshold or rare_tld is True:

            if entropy > entropy_threshold and rare_tld is True:
                flag_reason = "Both high entropy and rare TLD."
            elif rare_tld is True:
                flag_reason = "TLD is rare."
            elif entropy > entropy_threshold:
                flag_reason = "High shannon entropy value."

            if entropy > entropy_threshold and rare_tld is True:
                severity = "high"
            elif entropy > entropy_threshold or rare_tld is True:
                severity = "medium"

            alert = {
                    'detection_type': "dns_anomaly",
                    'src_ip': packet['src_ip'],
                    'queried_domain': packet['queried_domain'],
                    'tld': tld,
                    'entropy': entropy,
                    'flag_reason': flag_reason,
                    'severity': severity,
                }
            alerts.append(alert)
    return alerts