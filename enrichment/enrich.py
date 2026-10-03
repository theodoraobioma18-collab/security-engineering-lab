"""Enrich a list of IOCs (IPs and file hashes) with threat intel and write a CSV report."""
import argparse
import csv
import sys
import time
from collections import Counter

import requests

import check_hash
import check_ip
from ioc_types import detect_type, read_iocs

HASH_TYPES = {"md5", "sha1", "sha256"}
FIELDS = ["ioc", "ioc_type", "source", "verdict", "score", "context", "note"]


def call_with_retry(func, value, retries=3, wait=60):
    """Call an API function. If rate-limited (HTTP 429), wait and try again."""
    for attempt in range(1, retries + 1):
        try:
            return func(value)
        except requests.HTTPError as err:
            rate_limited = err.response is not None and err.response.status_code == 429
            if rate_limited and attempt < retries:
                print(f"    Rate limited. Waiting {wait}s (attempt {attempt}/{retries})...")
                time.sleep(wait)
            else:
                raise


def enrich_ip(ip):
    """Look up a public IP on AbuseIPDB and return report fields."""
    data = call_with_retry(check_ip.check_ip, ip)
    score = data["abuseConfidenceScore"]
    return {
        "source": "AbuseIPDB",
        "verdict": check_ip.verdict(score),
        "score": f"{score}/100",
        "context": f"{data.get('countryCode')} | {data.get('isp')} | {data.get('totalReports')} reports",
    }


def enrich_hash(file_hash):
    """Look up a file hash on VirusTotal and return report fields."""
    attrs = call_with_retry(check_hash.check_hash, file_hash)
    if attrs is None:
        return {"source": "VirusTotal", "verdict": "NOT FOUND"}
    stats = attrs.get("last_analysis_stats", {})
    label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
    return {
        "source": "VirusTotal",
        "verdict": check_hash.verdict(stats),
        "score": f"{stats.get('malicious', 0)}/{sum(stats.values())} engines",
        "context": f"{attrs.get('meaningful_name')} | {label}",
    }


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs with AbuseIPDB and VirusTotal.")
    parser.add_argument("-i", "--input", required=True, help="Text file with one IOC per line")
    parser.add_argument("-o", "--output", default="results.csv", help="CSV report path (default: results.csv)")
    parser.add_argument("--vt-delay", type=float, default=15,
                        help="Seconds between VirusTotal calls (free tier allows 4/min)")
    args = parser.parse_args()

    if not check_ip.API_KEY or not check_hash.API_KEY:
        sys.exit("ERROR: ABUSEIPDB_API_KEY or VT_API_KEY missing from .env")

    iocs = list(dict.fromkeys(read_iocs(args.input)))  # remove duplicates, keep order
    print(f"Loaded {len(iocs)} unique IOCs from {args.input}\n")

    rows = []
    last_vt_call = 0.0
    for n, ioc in enumerate(iocs, start=1):
        ioc_type = detect_type(ioc)
        row = {field: "" for field in FIELDS}
        row.update(ioc=ioc, ioc_type=ioc_type)

        try:
            if ioc_type == "ip":
                row.update(enrich_ip(ioc))
            elif ioc_type in HASH_TYPES:
                wait = args.vt_delay - (time.time() - last_vt_call)
                if wait > 0:
                    time.sleep(wait)  # stay under VirusTotal's rate limit
                last_vt_call = time.time()
                row.update(enrich_hash(ioc))
            elif ioc_type == "private_ip":
                row.update(verdict="SKIPPED", note="Private IP - not sent to external services")
            else:
                row.update(verdict="SKIPPED", note="Unrecognized IOC format")
        except requests.RequestException as err:
            row.update(verdict="ERROR", note=str(err)[:200])  # log it, keep going

        print(f"[{n}/{len(iocs)}] {row['verdict']:<14} {ioc_type:<11} {ioc}")
        rows.append(row)

    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nReport written to {args.output}")
    for verdict, count in Counter(r["verdict"] for r in rows).most_common():
        print(f"  {verdict:<14} {count}")


if __name__ == "__main__":
    main()