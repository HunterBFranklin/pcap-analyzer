# Development Log (most recent first)

My goal with this devlog is to show full authorship of this project in the age of AI coding.

**Sep. 6th, 2026 - 2:** threat_intel.py went pretty smoothly all things considered. I ran into some hurdles with indexing properly with the URLHaus URL CSV file, had to add in SSL and Certifi for download_feed() to work as I had planned, and had to cover a few edge cases I hadn't considered such as the CSV having some rows with fewer than three columns and it containing non-UTF-8 characters. After that was completed, I wanted to create a test, just as the other files, and this is where I troubleshooted the above issues. I finally got a return of "0" meaning there were no critical alerts for an IP or domain, so I hardcoded a known malicious IP source and it accurately reported the finding following the structure of analyze_threat_intel(). It has been commented out and was only used for validation of a working file. 

**Sep. 6th, 2026 - 1:** After completing dns_anomaly.py, I wanted to make a simple test, similar to beaconing.py and ingestor.py. I made a test with the sample malware pcap file, and ran it through analyze_dns(). I found that it correctly identified a suspicious dns and provided a full report per the parameters I added to analyze_dns() alerts. I will now be moving into threat_intel.py now that I've found analyze_dns() and dns_anomaly.py are working as expected.

**Sep. 5th, 2026 - 1:** Completed the implementation for is_rare_tld() and analyze_dns(). is_rare_tld() currently uses a hardcoded common suspicious list found from abuse.ch, though I do plan to implement it differently later as to make it changing over time. This function acts as a blocklist check to see if the TLD is a common suspicious TLD. analyze_dns() combines all of the functions to create an alert if the shannon entropy (high randomness of domain) or rare tld are found, which shows that a potentially suspicious dns was found. 

**Aug. 24, 2026 - 1:** Took some time to work on other certs and learning paths but now I am back to completing this project. I focused on completing the implementatons for dns_anomaly.py. is_rare_tld() detects the presence of a rare top level domain (known on a TLD blocklist set) that may indicate suspicious behavior/intentions. This is the final check before analyze all aspects of the DNS and DNS resolver. analyze_dns() calls the aforementioned functions and returns alert records for queries that are flagged.

**Aug. 12, 2026 - 1:** Didn't end up contributing to the project today so I decided to fill in protions of the README.md file. I will need to write in my short essay on why I created the tool and add what I learned after I complete it.

**Aug. 11, 2026 - 1:** Didn't have much time today. Only completed my psuedocode and logic for shannon_entropy(). This function will be used to test the randomness of a string to see if a DGA was used. I wasn't familiar with the formula, so I had to look it up. I'll add the source in my README. Tomorrow I plan to complete dns_anomaly.py fully and move on to threat_intel.py.

**Aug. 10, 2026 - 1:** Completed the implementation for get_sld() and get_tld() for the TLD blocklist check for analyze_dns().

**Aug. 9, 2026 - 1:** I began working on dns_anomaly.py. I used Scapy's haslayer() for guarding the queries to ensure they are within the right layer to be seen and to ensure the packet holds the necessary information for extraction. The purpose of this function is to extract all of the DNS queries from a raw packet and clean it up to be used it checking for DNS anomalies like DoH use, a DGA, or a random DNS resolver.

**Aug. 8, 2026 - 2:** I completed the beaconing.py implementation. I got pretty confused on how I wanted to structure the alert and what information was important for later files. The output works. I grabbed a sample malware packet to show a positive flag within the cv_threshold that I set (to 0.2) from malware-traffic-analysis.net. In later additions, I plan to let the user change the cv_threshold in CLI, making it adjustable rather than hardcoded. I was able to make a simple test using the sample pcap file and it worked; showing a single detection that was flagged as high severity and suspicious. I next plan to work on dns_anomaly.py.

**Aug. 8, 2026 - 1:** Checked back through ingestor.py and found that it could be 
optimized slightly. I want to begin working on the beaconing.py logic as that will
be the flagging of CV severity and alerts to anomalies. Now that I can ingest pcap files, I need to be able to flag them and check the five-tuple values. 

**Aug. 7, 2026 - 2:** Completed ingestor.py and feel good about the turnout. It successfully returns a five-tuple. I created a test to ensure it does (test_ingestor.py). I'm ready to move onto beaconing.py tomorrow.

**Aug. 7, 2026 - 1:** Creating files, project structure, and creating the project logic. Completed a majority of background research and am ready to make the psuedocode for each file. I'll be starting with ingestor.py as that is the main logic and everything else works around the packet capture. 
