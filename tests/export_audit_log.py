"""
tests/export_audit_log.py

Pulls every audit entry (from DynamoDB, or the local file if DynamoDB isn't
reachable) and prints them, plus writes tests/audit_export.json — handy for
pasting a table into the report.

Usage: python tests/export_audit_log.py
"""

import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from broker.audit_log import fetch_all_entries

OUT_PATH = Path(__file__).resolve().parent / "audit_export.json"


def main():
    entries = fetch_all_entries()
    print(f"{len(entries)} audit entries found.\n")
    for e in entries:
        print(f"{e.get('timestamp', '?'):30s} {e.get('decision', '?'):5s} "
              f"requester={e.get('requester_id', '?'):15s} object={e.get('object_id', '?')}")
    with open(OUT_PATH, "w") as f:
        json.dump(entries, f, indent=2, default=str)
    print(f"\nWritten to {OUT_PATH}")


if __name__ == "__main__":
    main()