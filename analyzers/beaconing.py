# =============================================================================
# pcap-analyzer — beaconing.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Aug. 7, 2026
# Modified    : Aug. 8, 2026
# =============================================================================

from statistics import stdev, mean
from datetime import datetime, timezone

def compute_intervals(timestamps: list[float]):

    """
    Computes the difference in arrival time, or intervals, and returns
    a list of inter-arrivals.
    """

    intervals = []
    for i in range(0, len(timestamps) - 1):
        diff = timestamps[i + 1] - timestamps[i]
        intervals.append(diff)

    return intervals


def compute_cv(intervals):

    """
    Divides the stdev by the mean of the intervals to get the coefficient
    of variation (CV). It also handles edge cases of an empty list or a mean
    of zero.
    """

    if len(intervals) == 0:
        return None

    interval_mean = mean(intervals)
    if interval_mean == 0:
        return None

    if len(intervals) < 2:
        return None
    cv = stdev(intervals, None) / interval_mean

    return cv


def is_beacon(intervals, cv_threshold: float, min_packets: int):

    """
    Returns True if the interval count meet the min. threshold and the CV
    falls below the cv_threshold. 
    """

    cv = compute_cv(intervals)
    if cv is None:
        return False

    if len(intervals) >= min_packets and cv < cv_threshold:
        return True
    return False


def analyze_beaconing(flows: dict, cv_threshold: float, min_packets: int):

    """
    Iterates through all flows, returning alert records for the flagged flows.
    """

    alerts = []

    for flow in flows:
        timestamps = flows[flow]
        intervals = compute_intervals(timestamps)
        cv = compute_cv(intervals)
        beacon = is_beacon(intervals, cv_threshold, min_packets)

        if beacon:
            if cv < 0.1:
                severity = "high"
            elif cv < 0.2:
                severity = "medium"
            else:
                severity = "low"

            last_packet_epoch = timestamps[-1]
            alert_timestamp = datetime.fromtimestamp(last_packet_epoch, tz=timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

            alert = {
                'timestamp': alert_timestamp,
                'detection_type': "beaconing",
                'src_ip': flow[0],
                'dst_ip': flow[1],
                'src_port': flow[2],
                'dst_port': flow[3],
                'protocol': flow[4],
                'packet_count': len(timestamps),
                'mean_interval_seconds': mean(intervals),
                'cv': cv,
                'severity': severity
            }
            alerts.append(alert)

    return alerts