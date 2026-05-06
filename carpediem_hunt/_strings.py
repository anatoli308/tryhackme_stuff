import re
from pathlib import Path

for f in ["decrypt_linux_amd64", "decrypt_win_amd64.exe"]:
    b = Path(f).read_bytes()
    strs = re.findall(rb"[ -~]{4,}", b)
    print("\n===", f, "===")
    shown = 0
    for s in strs:
        t = s.decode("latin1", "ignore")
        low = t.lower()
        if any(k in low for k in ["usage", "decrypt", "key", "flag", "database", "carp", "error", "output", "file"]):
            print(t)
            shown += 1
            if shown >= 150:
                break
