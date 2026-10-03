"""Check a file hash against VirusTotal and print a verdict."""
import os
import sys
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
URL = "https://www.virustotal.com/api/v3/files/{}"


def check_hash(file_hash):
    """Ask VirusTotal about one hash. Return its attributes, or None if VT has never seen it."""
    headers = {"x-apikey": API_KEY}
    response = requests.get(URL.format(file_hash), headers=headers, timeout=15)
    if response.status_code == 404:
        return None  # VT has no record of this file
    response.raise_for_status()
    return response.json()["data"]["attributes"]


def verdict(stats):
    """Turn antivirus engine results into an analyst-friendly label."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious >= 5:
        return "MALICIOUS"
    if malicious >= 1 or suspicious >= 1:
        return "SUSPICIOUS"
    return "NO DETECTIONS"


def format_date(timestamp):
    """Convert a Unix timestamp to YYYY-MM-DD."""
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")


def main():
    if not API_KEY:
        sys.exit("ERROR: VT_API_KEY not found. Check your .env file.")
    if len(sys.argv) != 2:
        sys.exit("Usage: python enrichment/check_hash.py <md5|sha1|sha256>")

    file_hash = sys.argv[1]
    attrs = check_hash(file_hash)

    if attrs is None:
        print(f"Hash:        {file_hash}")
        print("Verdict:     NOT FOUND (VirusTotal has never seen this file)")
        return

    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")

    print(f"Hash:        {file_hash}")
    print(f"Verdict:     {verdict(stats)}")
    print(f"Detections:  {stats.get('malicious', 0)}/{total} engines")
    print(f"File name:   {attrs.get('meaningful_name')}")
    print(f"File type:   {attrs.get('type_description')}")
    print(f"Threat label:{label}")
    print(f"First seen:  {format_date(attrs.get('first_submission_date'))}")


if __name__ == "__main__":
    main()