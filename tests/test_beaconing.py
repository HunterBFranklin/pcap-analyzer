
# Test for beaconing.py.

import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from ingestor import read_pcap, extract_flows
from analyzers.beaconing import analyze_beaconing

# ingestor.py reading and extracting:
malware_test = read_pcap("sample_malware_trace.pcap")
extract_test = extract_flows(malware_test)

alerts = analyze_beaconing(extract_test, cv_threshold=0.2, min_packets=5)
print(len(alerts))

for alert in alerts:
    print(alert)