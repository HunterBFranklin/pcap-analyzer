# PCAP Analyzer Tool

A Python command-line tool for behavioral network traffic analysis and anomaly detection. Designed to detect Command and Control (C2) communication patterns in captured or live network traffic.

## Authorship

This project was built incrementally and documented throughout; an effort to demonstrate full authorship in an age where AI-generated code is increasingly common. A [development log](DEVLOG.md) captures dated build decisions, development troubleshooting, and dead ends as they occurred.

## Why I Created the Tool

This project is the culmination of my continued learning in network analysis and in gaining more familiarity with Wireshark and its use cases. Oregon State’s CS 372 course opened my eyes to network analysis, and I’ve developed a strong interest in data, network protection, and network sniffing. As I’ve done more research on common cybersecurity tools and have started to understand all that goes into creating an informative SIEM tool, I wanted to start creating the underlying services for my SIEM: [HelmSIEM](https://github.com/HunterBFranklin/HelmSIEM). For this program, which is to be expanded, I opted to create my own network analysis tool instead of using a `zeek` API or `suricata`. Understanding that it would be harder to build every portion, I still wanted to create every aspect of the SIEM. Currently, HelmSIEM uses a Wazuh agent and an Elasticsearch/Logstash/Kibana (ELK) stack, and now this network analysis tool will be integrated. In addition, I had also heard of `scapy` and wanted to create a program that implemented it. My development log [DEVLOG.md] shows the process of troubleshooting and decision-making. In its current state, this tool can be used on pre-captured .pcap files (network packet capture) or on live network interface ports such as en0, en4, utun0, etc. I will be adding many features to get it more aligned with the functionality needed for HelmSIEM.

Let me dive into the build specifics, including how it’s used and what it provides for the user.

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
# Analyze a saved pcap file and save it to a new JSON file
python3 main.py --pcap capture.pcap --output results.json
 
# Live capture on en0 and save it to a new JSON file
sudo python3 main.py --live --iface en0 --output results.json
 
# Analyze pcap and output on stdout, adjusting detection thresholds
python3 main.py --pcap capture.pcap --cv-threshold 0.15 --min-packets 8 --entropy-threshold 3.8
 
# Force refresh threat intel feeds
python3 main.py --pcap capture.pcap --refresh
 
# Filter live capture to DNS traffic only
sudo python3 main.py --live --iface en0 --filter "port 53"
```

## CLI Flags
 
| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--pcap` | str | — | Path to a .pcap file for offline analysis |
| `--live` | bool | False | Enable live capture mode |
| `--packet-count` | int | 0 | Number of packets to capture in live mode |
| `--iface` | str | — | Network interface for live capture (e.g. en0, en4, en7) |
| `--output` | str | stdout | Path to write JSON results |
| `--refresh` | bool | False | Force re-download of threat intel feeds |
| `--filter` | str | — | Berkeley Packet Filter (BPF) expression |
| `--min-packets` | int | 5 | Minimum packet count per flow for beaconing analysis |
| `--cv-threshold` | float | 0.5 | CV cutoff for beaconing detection |
| `--entropy-threshold` | float | 3.5 | Shannon entropy cutoff for DNS anomaly detection |
| `--feeds-dir` | str | ./feeds | Directory to cache threat intelligence feeds |

## My Dependencies
 
```bash
pip install scapy
```
 
All other dependencies are in the Python standard library: `collections`, `statistics`, `math`, `argparse`, `json`, `csv`, `urllib`, `os`.
 
Requires `sudo` for live capture mode (raw socket access).

## Project Structure
 
```
pcap-analyzer/
├── main.py                  # CLI entry point
├── ingestor.py              # Pcap reading, live capture, flow extraction
├── output.py                # JSON and stdout formatting
├── analyzers/
│   ├── __init__.py          # Blank; import bugs and package support
│   ├── beaconing.py         # Inter-arrival time and CV analysis
│   ├── dns_anomaly.py       # TLD blocklist and Shannon entropy scoring
│   └── threat_intel.py      # Feed loading, caching, and IOC matching
├── feeds/                   # Cached threat intelligence files
│   ├── feodo_ip.txt         # Abuse.ch feodotracker for C2 IP blocklist
│   └── urlhaus_domains.csv  # Abuse.ch URLhaus for domain blocklist
├── tests/
│   ├── test_ingestor.py     # ingestor.py functionality test
│   ├── test_beaconing.py    # beaconing.py functionality test
│   ├── test_dns.py          # dns_anomaly.py funcationality test
│   └── test_threat.py       # threat_intel.py functionality test
├── sample.pcap              # Sample normal traffic trace
├── malware.pcap             # Sample malware traffic trace
├── ARCHITECTURE.md          # Design decisions and system overview
└── DEVLOG.md                # Build journal
```

## MITRE ATT&CK Mapping
 
| Technique | ID | Module |
|---|---|---|
| Application Layer Protocol | T1071 | Beaconing, DNS Anomaly, Threat Intel |
| Non-Standard Port | T1571 | Beaconing |
| Dynamic Resolution | T1568 | DNS Anomaly |
| Command and Control | TA0011 | All |

## What I Learned Building This

Here are some highlights of what I learned:
- **`scapy` outputs Decimal / EDecimal which can’t directly be serialized by Python’s JSON library.** This meant that I needed to create a class to encode the `scapy` output and convert it to float for JSON use.
- **`sudo` is only needed on live capture (via en0, utun0, etc.), not general capture of .pcap files.** This only really led to needing to change my READMe as functionality remained the same.
- **A VPN, network firewall/proxy, and network-level DoH largely impact the output of this program, as expected.** In testing all functionalities and outputs of the program, as expected, outputs ranged in quality as different services enabled changed output drastically. Disabling my VPN started to show some signs of life from live catpure, but I truly saw full captures at a live packet capture count of 10,000-25,000 and with all network protections disabled temporarily.
- **Python libraries `ssl` and `certifi` are needed for proper connection when downloading `threat_intel` feed files.** I learned this when troubleshooting why the feed files weren’t downloading while using test_threat.py.

## References

Abuse.ch. (2024). *Feodo Tracker -- botnet C2 IP blocklist*. https://feodotracker.abuse.ch
 
Abuse.ch. (2024). *URLhaus -- malware URL exchange*. https://urlhaus.abuse.ch
 
Biondi, P. (2023). *Scapy documentation*. https://scapy.readthedocs.io
 
Farnham, G., & Atlasis, A. (2013). *Detecting DNS tunneling*. SANS Institute. https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152
 
MITRE Corporation. (2024). *ATT&CK for Enterprise*. https://attack.mitre.org
 
Plohmann, D. et al. (2016). A comprehensive measurement study of domain generating malware. *USENIX Security*. https://www.usenix.org/conference/usenixsecurity16
 
Rao, V. (2013). *Detecting beaconing activity from pcap files*. SANS Institute. https://www.sans.org/reading-room/whitepapers/detection/detecting-beaconing-activity-pcap-files-34352
 
Tranco List Project. (2024). https://tranco-list.eu


