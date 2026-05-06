"""Look up real Bitcoin transactions to the ransom wallet using Blockstream's
public mempool API. If the challenge follows the typical TryHackMe ransomware
pattern, one of the senders is the valid 'proof' wallet.
"""
from __future__ import annotations

import json

import httpx

WALLET = "bc1q989cy4zp8x9xpxgwpznsxx44u0cxhyjjyp78hj"


def main() -> None:
    base = "https://blockstream.info/api"
    with httpx.Client(timeout=20) as c:
        info = c.get(f"{base}/address/{WALLET}").json()
        print("address summary:")
        print(json.dumps(info, indent=2))

        txs = c.get(f"{base}/address/{WALLET}/txs").json()
        print(f"\n{len(txs)} txs returned")

        senders: set[str] = set()
        for tx in txs:
            for vin in tx.get("vin", []):
                p = vin.get("prevout", {})
                addr = p.get("scriptpubkey_address")
                if addr:
                    senders.add(addr)

        print("\nunique sender addresses:")
        for s in sorted(senders):
            print(" ", s, "len", len(s))


if __name__ == "__main__":
    main()
