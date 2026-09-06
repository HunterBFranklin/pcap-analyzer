# PCAP Analyzer Tool

A Python command-line tool for behavioral network traffic analysis and anomaly detection. Designed to detect Command and Control (C2) communication patterns in captured or live network traffic.

## Authorship

This project was built incrementally and documented throughout; an effort to demonstrate full authorship in an age where AI-generated code is increasingly common. A [development log](DEVLOG.md) captures dated build decisions and dead ends as they happened.

## Why I Created the Tool

[To be added]

## Use Cases
 
- Detecting C2 beaconing behavior in captured network traffic from an unknown host
- Flagging algorithmically generated domains indicative of malware Domain Generation Algorithm (DGA) activity
- Correlating observed traffic against public threat intelligence feeds for known-bad infrastructure
- Auditing live network interfaces for suspicious outbound communication patterns
- Supplementing a host-based Security Information and Event Management (SIEM) with network-layer behavioral detection (this is what I plan to do)

## How It Works
 
The program reads either a saved .pcap file or captures live traffic from a specified network interface. Packets are parsed into flow records keyed by five-tuple (source IP, destination IP, source port, destination port, protocol). Three independent detection modules then analyze the flow data in parallel and produce structured alert records.

Each alert includes a severity rating, MITRE ATT&CK technique mapping, and detection-specific evidence fields. Results are written as a JavaScript Object Notation (JSON) array and summarized in a human-readable stdout report.
 
## Tests
 
| # | Module | What It Checks |
|---|---|---|
| 1 | Beaconing | Flags flows with CV below threshold and packet count above minimum |
| 2 | DNS Anomaly | Flags queries with rare TLDs or Shannon entropy above threshold |
| 3 | Threat Intel | Flags flows destined for known-bad IPs or domains |
 
## Usage
 
```bash
# Analyze a saved pcap file
sudo python3 main.py --pcap capture.pcap --output results.json
 
# Live capture on eth0
sudo python3 main.py --live --iface eth0 --output results.json
 
# Adjust detection thresholds
sudo python3 main.py --pcap capture.pcap --cv-threshold 0.15 --min-packets 8 --entropy-threshold 3.8
 
# Force refresh threat intel feeds
sudo python3 main.py --pcap capture.pcap --refresh
 
# Filter live capture to DNS traffic only
sudo python3 main.py --live --iface eth0 --filter "port 53"
```

## CLI Flags
 
| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--pcap` | str | — | Path to a .pcap file for offline analysis |
| `--live` | bool | False | Enable live capture mode |
| `--iface` | str | — | Network interface for live capture (e.g. eth0) |
| `--output` | str | stdout | Path to write JSON results |
| `--refresh` | bool | False | Force re-download of threat intel feeds |
| `--filter` | str | — | Berkeley Packet Filter (BPF) expression |
| `--min-packets` | int | 10 | Minimum packet count per flow for beaconing analysis |
| `--cv-threshold` | float | 0.2 | CV cutoff for beaconing detection |
| `--entropy-threshold` | float | 3.5 | Shannon entropy cutoff for DNS anomaly detection |

## My Dependencies
 
```bash
pip install scapy
```
 
All other dependencies are in the Python standard library: `collections`, `statistics`, `math`, `argparse`, `json`, `csv`, `urllib`, `os`.
 
Requires `sudo` for live capture mode (raw socket access).

## Project Structure
 
```
pcap-sentinel/
├── main.py                  # CLI entry point
├── ingestor.py              # Pcap reading, live capture, flow extraction
├── output.py                # JSON and stdout formatting
├── analyzers/
│   ├── beaconing.py         # Inter-arrival time and CV analysis
│   ├── dns_anomaly.py       # TLD blocklist and Shannon entropy scoring
│   └── threat_intel.py      # Feed loading, caching, and IOC matching
├── feeds/                   # Cached threat intelligence files
├── ARCHITECTURE.md          # Design decisions and system overview
├── DEVLOG.md                # Build journal
└── NOTES.md                 # Development scratch pad
```

## MITRE ATT&CK Mapping
 
| Technique | ID | Module |
|---|---|---|
| Application Layer Protocol | T1071 | Beaconing, DNS Anomaly, Threat Intel |
| Non-Standard Port | T1571 | Beaconing |
| Dynamic Resolution | T1568 | DNS Anomaly |
| Command and Control | TA0011 | All |

## What I Learned Building This

[To be added]

## References

Abuse.ch. (2024). *Feodo Tracker -- botnet C2 IP blocklist*. https://feodotracker.abuse.ch
 
Abuse.ch. (2024). *URLhaus -- malware URL exchange*. https://urlhaus.abuse.ch
 
Biondi, P. (2023). *Scapy documentation*. https://scapy.readthedocs.io
 
Farnham, G., & Atlasis, A. (2013). *Detecting DNS tunneling*. SANS Institute. https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152
 
MITRE Corporation. (2024). *ATT&CK for Enterprise*. https://attack.mitre.org
 
Plohmann, D. et al. (2016). A comprehensive measurement study of domain generating malware. *USENIX Security*. https://www.usenix.org/conference/usenixsecurity16
 
Rao, V. (2013). *Detecting beaconing activity from pcap files*. SANS Institute. https://www.sans.org/reading-room/whitepapers/detection/detecting-beaconing-activity-pcap-files-34352
 
Tranco List Project. (2024). https://tranco-list.eu


