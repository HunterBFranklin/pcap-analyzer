# =============================================================================
# pcap-analyzer — threat_intel.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Aug. 7, 2026
# Modified    : Sep. 6, 2026
# =============================================================================

import urllib.request
from urllib.parse import urlparse
import os, os.path
import csv
import time

import ssl
import certifi

def is_feed_stale(filepath: str, max_age_hours: int):

    """
    Checks if a cached feed file is older than the maximum allowed age. Returns
    True if the file should be refreshed and False if the file is still current.
    """

    file_age = time.time() - os.path.getmtime(filepath)
    if file_age > (max_age_hours * 3600):
        return True
    return False


def download_feed(url: str, dest_path: str):

    """
    Fetches the feed file from url using urllib.request and saves it.
    """

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(url, context=ssl_context) as response:
        with open(dest_path, 'wb') as f:
            f.write(response.read())


def parse_ip_feed(filepath: str):

    """
    Opens a threat intel IP feed file, skips comment lines beginning with "#",
    strips whitespace, and returns a set of IP address strings for O(1) lookup.
    """

    ip_addresses = set()
    with open(filepath, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            line = line.strip()
            ip_addresses.add(line)
    return ip_addresses


def parse_domain_feed(filepath: str):


    """
    Opens a threat intel URL/Domain CSV file, skips comment lines beginning with "#",
    uses urlparse to maintain just IP/hostname, and returns a set of domain strings for O(1) lookup.
    """

    domains = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            if row[0].startswith("#"):
                continue
            if len(row) < 3:
                continue
            domain = urlparse(row[2]).hostname
            domains.add(domain)
    return domains


def load_feeds(feeds_dir: str, force_refresh: bool):

    """
    Orchestrates feed loading by checking staleness, downloading if needed, parsing each
    feed with the appropariate parser, and returning a tuple of (ip_set, domain_set) for
    use in threat intel matching.
    """

    os.makedirs(feeds_dir, exist_ok=True)
    feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    feodo_path = os.path.join(feeds_dir, "feodo_ip.txt")
    urlhaus_url = "https://urlhaus.abuse.ch/downloads/csv/"
    urlhaus_path = os.path.join(feeds_dir, "urlhaus_domains.csv")

    if force_refresh or not os.path.exists(feodo_path) or is_feed_stale(feodo_path, max_age_hours=6):
        download_feed(feodo_url, feodo_path)
    if force_refresh or not os.path.exists(urlhaus_path) or is_feed_stale(urlhaus_path, max_age_hours=6):
        download_feed(urlhaus_url, urlhaus_path)

    feodo_ip = parse_ip_feed(feodo_path)
    urlhaus_domain = parse_domain_feed(urlhaus_path)

    return (feodo_ip, urlhaus_domain)

def analyze_threat_intel(flows: dict, ip_blocklist: set, domain_blocklist: set):

    """
    Iterates through all flows and checks the destination IP against the IP and domain
    blocklists. Returns "critical" severity alert records for any matches against confirmed
    malicious infrastructure.
    """

    alerts = []

    for flow in flows:
        if flow[1] in ip_blocklist or flow[1] in domain_blocklist:
            if flow[1] in ip_blocklist:
                source = "feodo_tracker"
            elif flow[1] in domain_blocklist:
                source = "urlhaus"
            alert = {
                'detection_type': "threat_intel",
                'src_ip': flow[0],
                'dst_ip': flow[1],
                'dst_port': flow[3],
                'protocol': flow[4],
                'feed_source': source,
                'severity': "critical",
                'MITRE_technique': "T1071",
                'MITRE_tactic': "TA0011: Command and Control (C2)"
            }
            alerts.append(alert)
        
    return alerts
