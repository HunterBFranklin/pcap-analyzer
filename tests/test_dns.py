
# Test for dns_anomaly.py.

import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from ingestor import read_pcap, extract_flows
from analyzers.dns_anomaly import analyze_dns, SUSPICIOUS_TLDS

malware_test = read_pcap("sample_malware_trace.pcap")
alerts = analyze_dns(malware_test, tld_blocklist=SUSPICIOUS_TLDS, entropy_threshold=3.5)
print(len(alerts))

for alert in alerts:
    print(alert)