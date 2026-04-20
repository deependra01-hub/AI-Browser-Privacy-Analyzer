"""Send sample request traffic to the local backend."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

API_URL = "http://localhost:8000/analyze"
SAMPLE_FILE = Path(__file__).with_name("sample_requests.json")


def main() -> None:
    payloads = json.loads(SAMPLE_FILE.read_text(encoding="utf-8"))
    for payload in payloads:
        request = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                print(f"{payload['domain']}: {response.status}")
        except urllib.error.URLError as exc:
            print(f"Failed to send {payload['domain']}: {exc}")


if __name__ == "__main__":
    main()
