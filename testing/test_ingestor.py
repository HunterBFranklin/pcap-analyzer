# Test for ingestor.py.

import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from ingestor import read_pcap, extract_flows

# read_pcap() test:
read_test = read_pcap("sample_trace.pcap")
print(read_test)

# extract_flows() test:
extract_test = extract_flows(read_test)
print(len(extract_test))
print(list(extract_test.items())[0])