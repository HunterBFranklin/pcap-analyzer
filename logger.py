# =============================================================================
# pcap-analyzer — logger.py
# GitHub Repo : github.com/HunterBFranklin/pcap-analyzer
# Created     : Sep. 7, 2026
# Modified    : Sep. 7, 2026
# =============================================================================

import logging
import sys

def get_logger(name: str) -> logging.logger:

    """
    
    """

    logger = logging.getLogger(name)

    # Prevents duped handlers
    if not logger.handlers:
        logger.setLevel(logging.INFO)

        handler = logging.StreamHandler(sys.stderr)

        # ISO 8601 Z standardization
        formatter = logging.Formatter(
            fmt='%(asctime)s.%(msecs)03dZ [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger