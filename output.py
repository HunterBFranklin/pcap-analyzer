# =============================================================================
# pcap-analyzer — output.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Aug. 7, 2026
# Modified    : Sep. 6, 2026
# =============================================================================

import json
import sys
import datetime
from decimal import Decimal

class DecimalEncoder(json.JSONEncoder):

    """
    Custom JSON encoder to handle Scapy's EDecimal/Decimal timestamp types.
    """

    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)

def build_alert(detection_type: str, src_ip: str, dst_ip: str, severity: str, detail: dict):

    """
    Builds an alert with the timestamp, detection type, source and dest. IP, severity,
    MITRE technique and tactic, and provides more specific detail.
    """

    iso_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

    return {
        'timestamp': iso_timestamp,
        'detection_type': detection_type,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'severity': severity,
        'mitre_technique': "T1071",
        "mitre_tactic": "TA0011 - Command and Control (C2)",
        'detail': detail
    }


def write_json(alerts: list, output_path: str | None):

    """
    Serializes the alerts list to JSON and writes to a file if output_path is provided,
    otherwise prints formatted JSON to stdout. Uses DecimalEncoder to handle EDecimal types.
    """

    if output_path:
        with open(output_path, "w") as f:
            json.dump(alerts, f, indent=2, cls=DecimalEncoder)
    else:
        print(json.dumps(alerts, indent=2, cls=DecimalEncoder))


def print_summary(alerts: list, flows_analyzed: int, output_path: str | None):

    """
    Prints a human-readable summary of the analysis run showing flow count, alert counts, 
    by detection type, total alerts, and output path.
    """

    beaconing = len([a for a in alerts if a['detection_type'] == 'beaconing'])
    dns_anomalies = len([a for a in alerts if a['detection_type'] == 'dns_anomaly'])
    threat_intel = len([a for a in alerts if a['detection_type'] == 'threat_intel'])
    total = beaconing + dns_anomalies + threat_intel

    print("pcap-analyzer results")
    print("---------------------")
    print(f"{'Flows analyzed:':<25} {flows_analyzed}")
    print(f"{'Beaconing alerts:':<25} {beaconing}")
    print(f"{'DNS anomaly alerts:':<25} {dns_anomalies}")
    print(f"{'Threat intel hits:':<25} {threat_intel}")
    print(f"{'Total alerts:':<25} {total}")
    print(f"{'Output written to:':<25} {output_path if output_path else 'stdout'}")