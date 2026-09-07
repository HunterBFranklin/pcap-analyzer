
# Test for threat_intel.py.

import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from ingestor import read_pcap, extract_flows
from analyzers.threat_intel import load_feeds, analyze_threat_intel

# ingestor.py reading and extracting:
malware_test = read_pcap("sample_malware_trace.pcap")
extract_test = extract_flows(malware_test)

ip_set, domain_set = load_feeds("feeds", force_refresh=False)
# ip_set.add("10.2.28.88") # For validation.
alerts = analyze_threat_intel(extract_test, ip_set, domain_set)
print(len(alerts))

for alert in alerts:
    print(alert)