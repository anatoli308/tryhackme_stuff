from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import urlparse

from .auth import authenticate_with_candidates
from .extractors import merge_unique
from .http_client import HttpClient
from .recon import run_recon
from .report import HuntReport
from .tamper import fetch_dashboard_flag, run_post_auth_probes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Semi-universal THM web hunt framework (recon -> auth -> tamper)."
    )
    parser.add_argument("--target", required=True, help="Base URL, e.g. http://10.114.136.231")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument(
        "--extra-path",
        action="append",
        default=[],
        help="Additional path to probe during recon (can be repeated)",
    )
    parser.add_argument(
        "--email",
        action="append",
        default=[],
        help="Manual email candidate (can be repeated)",
    )
    parser.add_argument(
        "--password",
        action="append",
        default=[],
        help="Manual password candidate (can be repeated)",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional output file for JSON report",
    )
    args = parser.parse_args()
    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        parser.error(f"Invalid target URL: {args.target}")
    return args


def main() -> int:
    args = parse_args()
    client = HttpClient(base_url=args.target, timeout=args.timeout)

    recon = run_recon(client, extra_paths=args.extra_path)

    report = HuntReport(
        target=args.target,
        discovered_paths=recon.discovered,
        backup_hits=sorted(recon.backup_hits.keys()),
        leaked_emails=recon.leaked_emails,
    )

    default_emails = ["admin", "administrator", "root"]
    emails = merge_unique(default_emails + recon.leaked_emails + args.email)

    passwords = merge_unique(recon.password_candidates + args.password)

    auth_ctx = authenticate_with_candidates(client, emails, passwords)
    report.credential_used = auth_ctx

    if auth_ctx:
        report.admin_flag = fetch_dashboard_flag(client)
        report.post_auth_findings = run_post_auth_probes(client)

    report.print_human()

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.write_text(report.to_json(), encoding="utf-8")
        print(f"\n[+] JSON report written to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
