"""Detect what kind of indicator of compromise (IOC) a string is."""
import ipaddress
import re
import sys

HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}


def detect_type(value):
    """Return 'ip', 'private_ip', 'md5', 'sha1', 'sha256', or 'unknown'."""
    value = value.strip()

    # Is it an IP address?
    try:
        ip = ipaddress.ip_address(value)
        return "ip" if ip.is_global else "private_ip"
    except ValueError:
        pass  # not an IP, keep checking

    # Is it a file hash?
    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return hash_type

    return "unknown"


def read_iocs(path):
    """Read IOCs from a file, skipping blank lines and # comments."""
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f
                if line.strip() and not line.strip().startswith("#")]


if __name__ == "__main__":
    # Quick test: python enrichment/ioc_types.py enrichment/sample_iocs.txt
    for ioc in read_iocs(sys.argv[1]):
        print(f"{detect_type(ioc):<12} {ioc}")