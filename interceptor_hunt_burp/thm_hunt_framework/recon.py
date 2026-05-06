from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .extractors import extract_emails
from .http_client import HttpClient

DEFAULT_DISCOVERY_PATHS = [
    "",
    "index.php",
    "login.php",
    "dashboard.php",
    "search.php",
    "otp.php",
    "verify_otp.php",
    "api_login.php",
    "import_feed_api.php",
]

BACKUP_SUFFIXES = [".bak", "~", ".old", ".backup"]
INTERESTING_STATUS_CODES = {200, 301, 302, 401, 403}
GENERIC_PAGE_SIZE_THRESHOLD = 1700


@dataclass
class ReconData:
    discovered: list[str] = field(default_factory=list)
    backup_hits: dict[str, str] = field(default_factory=dict)
    leaked_emails: list[str] = field(default_factory=list)
    password_candidates: list[str] = field(default_factory=list)


def generate_password_candidates(current_year: int | None = None) -> list[str]:
    year = current_year or datetime.now().year
    values = [year, year - 1, year + 1, year - 2, year + 2]
    return [f"MediaHub{y}" for y in values]


def run_recon(client: HttpClient, extra_paths: list[str] | None = None) -> ReconData:
    data = ReconData(password_candidates=generate_password_candidates())
    paths = list(DEFAULT_DISCOVERY_PATHS)
    if extra_paths:
        paths.extend(extra_paths)

    for path in paths:
        result = client.request("GET", path)
        if result.status_code == 0:
            continue
        if result.status_code in INTERESTING_STATUS_CODES:
            data.discovered.append(path or "/")

    for seed in ["login.php", "dashboard.php", "verify_otp.php", "search.php"]:
        for suffix in BACKUP_SUFFIXES:
            candidate = f"{seed}{suffix}"
            result = client.request("GET", candidate)
            if result.status_code != 200:
                continue
            if (
                "welcome to mediahub" in result.text.lower()
                and len(result.text) < GENERIC_PAGE_SIZE_THRESHOLD
            ):
                # Likely generic fallback page.
                continue
            data.backup_hits[candidate] = result.text

    leaked = []
    for content in data.backup_hits.values():
        leaked.extend(extract_emails(content))
    data.leaked_emails = sorted(set(leaked))

    return data
