# =============================================================================
# pcap-analyzer — config_loader.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Sep. 8, 2026
# Modified    : Sep. 8, 2026
# =============================================================================

import json
import os
import ipaddress
from logger import get_logger

logger = get_logger("pcap-analyzer.config")

def load_config(config_path: str = "config.json") -> dict:
    """
    Loads the configuration file. Returns default empty filters if file is missing.
    """
    if not os.path.exists(config_path):
        logger.warning(f"Config file '{config_path}' not found. Running with zero whitelists.")
        return {"whitelist": {"subnets": [], "ignored_domains": []}}

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            logger.info(f"Successfully loaded configuration from {config_path}")
            return config
    except Exception as e:
        logger.error(f"Failed to parse config file {config_path}: {e}")
        return {"whitelist": {"subnets": [], "ignored_domains": []}}


def is_ip_whitelisted(ip_str: str, whitelisted_nets: list) -> bool:
    """
    Checks if a given IP address falls within any whitelisted IP or CIDR subnet.
    """
    try:
        target_ip = ipaddress.ip_address(ip_str)
        for net_str in whitelisted_nets:
            if target_ip in ipaddress.ip_network(net_str, strict=False):
                return True
    except ValueError:
        pass
    return False


def is_domain_ignored(domain: str, ignored_suffixes: list) -> bool:
    """
    Checks if a domain ends with any of the ignored domain suffixes.
    """
    for suffix in ignored_suffixes:
        if domain.endswith(suffix):
            return True
    return False