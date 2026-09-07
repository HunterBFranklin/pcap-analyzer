# =============================================================================
# pcap-analyzer — main.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Aug. 7, 2026
# Modified    : Sep. 7, 2026
# =============================================================================

import argparse
import ingestor
import output
import traceback
from analyzers import beaconing, dns_anomaly, threat_intel

def parse_args():

    """
    Defines and parses all CLI flags: --pcap, --live, --iface, --output, --refresh,
    --filter, --min-packets, --cv-threshold, and --entropy--threshold.
    """

    parser = argparse.ArgumentParser(description="Pcap-analyzer: A behavioral network analysis tool.")

    parser.add_argument("--pcap", type=str, help="Path to the PCAP file to analyze.")
    parser.add_argument("--live", action="store_true", help="Capture live network traffic.")
    parser.add_argument("--iface", type=str, help="Network interface for live capture.")

    parser.add_argument("--output", type=str, default="stdout", help="Destination for generated alerts.")
    parser.add_argument("--refresh", action="store_true", help="Force refresh of threat intelligence feeds.")
    parser.add_argument("--filter", type=str, help="BPF packet filter expression.")

    parser.add_argument("--min-packets", type=int, default=5, help="Minimum packets required for beaconing analysis.")
    parser.add_argument("--cv-threshold", type=float, default=0.5, help="Coefficient of variation threshold for beaconing.")
    parser.add_argument("--entropy-threshold", type=float, default=3.0, help="Entropy threshold for DNS anomaly detection.")
    parser.add_argument("--feeds-dir", type=str, default="./feeds", help="Directory to cache threat intelligence feeds.")
    parser.add_argument("--packet-count", type=int, default=0, help="Number of packets to capture in live mode.")

    return parser.parse_args()

def main():

    """
    Orchestrates the full pipeline: parse args, call ingestor, load feeds, 
    run all three analyzers, collect returned alert lists, pass combined 
    alerts to output functions.
    """

def main():
    try:
        print("[DEBUG] Entering main()...")
        args = parse_args()
        print(f"[DEBUG] Arguments parsed successfully.")

        if args.pcap:
            print(f"[DEBUG] Reading PCAP file: {args.pcap}")
            packets = ingestor.read_pcap(args.pcap)
        elif args.live:
            bpf_filter = args.filter if args.filter else ""
            print(f"[DEBUG] Starting live capture on interface {args.iface}...")
            packets = ingestor.start_live_capture(iface=args.iface, packet_count=args.packet_count, bpf_filter=bpf_filter)
        else:
            print("[ERROR] Neither --pcap nor --live was specified.")
            return

        print(f"[DEBUG] Loaded {len(packets)} packets. Extracting flows...")
        flows = ingestor.extract_flows(packets)
        print(f"[DEBUG] Extracted {len(flows)} unique flows. Loading threat intel feeds...")

        ip_blocklist, domain_blocklist = threat_intel.load_feeds(
            feeds_dir=args.feeds_dir,
            force_refresh=args.refresh
        )
        print(f"[DEBUG] Threat intel loaded. Running analyzers...")

        alerts = []

        beacon_alerts = beaconing.analyze_beaconing(
            flows, 
            cv_threshold=args.cv_threshold, 
            min_packets=args.min_packets
        )
        alerts.extend(beacon_alerts)

        dns_alerts = dns_anomaly.analyze_dns(
            packets, 
            tld_blocklist=dns_anomaly.SUSPICIOUS_TLDS, 
            entropy_threshold=args.entropy_threshold
        )
        alerts.extend(dns_alerts)

        ti_alerts = threat_intel.analyze_threat_intel(
            flows, 
            ip_blocklist=ip_blocklist, 
            domain_blocklist=domain_blocklist
        )
        alerts.extend(ti_alerts)

        print(f"[DEBUG] Analysis complete. Total alerts found: {len(alerts)}. Printing output...")
        output_path = None if args.output == "stdout" else args.output
        output.write_json(alerts, output_path)
        output.print_summary(alerts, len(flows), output_path)

    except Exception as e:
        print("\n[CRITICAL ERROR] An exception occurred during execution:")
        traceback.print_exc()

if __name__ == "__main__":
    main()