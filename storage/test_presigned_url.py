"""
storage/test_presigned_url.py

Standalone proof that generate_presigned_url() works end-to-end:
1. Generates a short-lived URL for a real object in your bucket.
2. Downloads it immediately -> should succeed (200).
3. Waits past expiry.
4. Downloads it again -> should fail (403).

Usage:
    python test_presigned_url.py <object_key> [expiry_seconds]

Example:
    python test_presigned_url.py test1.txt 10
"""

import sys
import time
import requests

from s3_client import generate_presigned_url


def main():
    object_key = sys.argv[1] if len(sys.argv) > 1 else "test1.txt"
    expiry = int(sys.argv[2]) if len(sys.argv) > 2 else 10  # keep short so the test finishes fast

    print(f"[1/4] Generating presigned URL for '{object_key}' (expires in {expiry}s)...")
    url = generate_presigned_url(object_key, expiry_seconds=expiry)
    print(f"      URL: {url}\n")

    print("[2/4] Downloading immediately (expect 200 OK)...")
    resp = requests.get(url, timeout=10)
    print(f"      Status: {resp.status_code}")
    if resp.status_code == 200:
        print(f"      PASS — downloaded {len(resp.content)} bytes.\n")
    else:
        print(f"      FAIL — response body:\n{resp.text}\n")
        sys.exit(1)

    wait = expiry + 5
    print(f"[3/4] Waiting {wait}s for the URL to expire...")
    time.sleep(wait)

    print("[4/4] Downloading again after expiry (expect 403 Forbidden)...")
    resp2 = requests.get(url, timeout=10)
    print(f"      Status: {resp2.status_code}")
    if resp2.status_code == 403:
        print("      PASS — URL correctly expired.")
    else:
        print(f"      FAIL — expected 403, got {resp2.status_code}:\n{resp2.text}")
        sys.exit(1)


if __name__ == "__main__":
    main()
