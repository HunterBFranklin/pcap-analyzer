# Development Log (most recent first)

My goal with this devlog it to show full authorship in the AI age of coding.

**Aug. 8, 2026 - 2:** I completed the beaconing.py implementation. I got pretty confused on how I wanted to structure the alert and what information was important for later files. The output works. I grabbed a sample malware packet to show a positive flag within the cv_threshold that I set (to 0.2) from malware-traffic-analysis.net. In later additions, I plan to let the user change the cv_threshold in CLI, making it adjustable rather than hardcoded. I was able to make a simple test using the sample pcap file and it worked; showing a single detection that was flagged as high severity and suspicious. I next plan to work on dns_anomaly.py.

**Aug. 8, 2026 - 1:** Checked back through ingestor.py and found that it could be 
optimized slightly. I want to begin working on the beaconing.py logic as that will
be the flagging of CV severity and alerts to anomalies. Now that I can ingest pcap files, I need to be able to flag them and check the five-tuple values. 

**Aug. 7, 2026 - 2:** Completed ingestor.py and feel good about the turnout. It successfully returns a five-tuple. I created a test to ensure it does (test_ingestor.py). I'm ready to move onto beaconing.py tomorrow.

**Aug. 7, 2026 - 1:** Creating files, project structure, and creating the project logic. Completed a majority of background research and am ready to make the psuedocode for each file. I'll be starting with ingestor.py as that is the main logic and everything else works around the packet capture. 
