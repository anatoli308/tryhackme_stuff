"""Romance & Co recon: port scan + path enumeration on Next.js app."""
import socket
import concurrent.futures as cf
import requests
import sys

TARGET = "10.114.144.103"
BASE = f"http://{TARGET}:3000"

PORTS = [21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
         1433, 1521, 2049, 2375, 2376, 2483, 3000, 3001, 3306, 3389,
         4000, 4200, 4369, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443,
         7000, 7474, 8000, 8008, 8080, 8081, 8443, 8888, 8983, 9000, 9090,
         9092, 9200, 9300, 11211, 15672, 25565, 27017, 27018, 50000, 50070]


def scan_port(p):
    try:
        with socket.create_connection((TARGET, p), timeout=1.5) as s:
            return p
    except Exception:
        return None


def banner(p):
    try:
        r = requests.get(f"http://{TARGET}:{p}/", timeout=3)
        return p, r.status_code, r.headers.get("Server", ""), r.headers.get("X-Powered-By", ""), r.headers.get("Content-Type", "")[:40], r.text[:120].replace("\n", " ")
    except Exception as e:
        return p, "ERR", str(e)[:60], "", "", ""


PATHS = [
    "/api", "/api/", "/api/users", "/api/user", "/api/login", "/api/register",
    "/api/auth", "/api/auth/login", "/api/auth/register", "/api/admin",
    "/api/products", "/api/orders", "/api/contact", "/api/bookings",
    "/api/booking", "/api/experiences", "/api/health", "/api/status",
    "/api/v1", "/api/v1/users", "/api/feedback", "/api/upload", "/api/files",
    "/api/search", "/api/profile", "/api/posts", "/api/comments", "/api/cart",
    "/login", "/signup", "/register", "/admin", "/dashboard", "/profile",
    "/account", "/users", "/cart", "/checkout", "/booking", "/bookings",
    "/experiences", "/blog", "/posts", "/.git/HEAD", "/.env", "/server-status",
    "/_next/data", "/uploads", "/static", "/public", "/admin/login",
    "/api/debug", "/api/config", "/api/info", "/graphql", "/.well-known/security.txt",
]


def probe(path):
    try:
        r = requests.get(BASE + path, timeout=5, allow_redirects=False)
        return path, r.status_code, len(r.content), r.headers.get("Location", ""), r.headers.get("Content-Type", "")[:40]
    except Exception as e:
        return path, "ERR", 0, str(e)[:50], ""


def main():
    print("[*] Port scan ...")
    open_ports = []
    with cf.ThreadPoolExecutor(64) as ex:
        for r in ex.map(scan_port, PORTS):
            if r:
                open_ports.append(r)
    print("[+] Open ports:", open_ports)
    for p in open_ports:
        print(banner(p))

    print("\n[*] Path probe on :3000 ...")
    interesting = []
    with cf.ThreadPoolExecutor(20) as ex:
        for res in ex.map(probe, PATHS):
            path, code, size, loc, ct = res
            if code in ("ERR",) or code == 404:
                continue
            interesting.append(res)
            print(f"  {code} {size:>6}  {path}  {loc}  {ct}")
    print("\n[+] Interesting count:", len(interesting))


if __name__ == "__main__":
    main()
