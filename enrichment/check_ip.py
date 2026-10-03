"""Check an IP address against AbuseIPDB and print a verdict."""
import os
import sys

import requests
from dotenv import load_dotenv

# Load secrets from the .env file into environment variables
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip):
    """Ask AbuseIPDB about one IP and return the 'data' part of the response."""
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(URL, headers=headers, params=params, timeout=10)
    response.raise_for_status()  # stop with an error if the status isn't 2xx
    return response.json()["data"]


def verdict(score):
    """Turn the 0-100 abuse score into an analyst-friendly label."""
    if score >= 75:
        return "MALICIOUS"
    if score >= 25:
        return "SUSPICIOUS"
    return "CLEAN"


def main():
    if not API_KEY:
        sys.exit("ERROR: ABUSEIPDB_API_KEY not found. Check your .env file.")
    if len(sys.argv) != 2:
        sys.exit("Usage: python enrichment/check_ip.py <ip-address>")

    ip = sys.argv[1]
    data = check_ip(ip)
    score = data["abuseConfidenceScore"]

    print(f"IP:             {data['ipAddress']}")
    print(f"Abuse score:    {score}/100")
    print(f"Verdict:        {verdict(score)}")
    print(f"Country:        {data.get('countryCode')}")
    print(f"ISP:            {data.get('isp')}")
    print(f"Usage type:     {data.get('usageType')}")
    print(f"Total reports:  {data.get('totalReports')}")
    print(f"Last reported:  {data.get('lastReportedAt')}")


if __name__ == "__main__":
    main()