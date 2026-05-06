import itertools
import subprocess
from pathlib import Path

keys = [
    "bDRkNUliRGNpUFlZRmR6RE1VZXpOSkkxWFUxa3dSTkRlQVhIai45ZGlMVFhFSGJQN1U2c01GWlZscUVrY19jVw==",
    "OVB0Vy4ua3FBZnZoMThmM3g1dGFxOHVVdXFfanNCa1hLQ1pPUFZCTTJQUk9fWFN1ZlliRS5fZXBRSDU4aUVmZA==",
]

exe = Path("decrypt_win_amd64.exe")
if not exe.exists():
    raise SystemExit("missing decrypt_win_amd64.exe")

# cleanup old outputs
for p in Path(".").glob("bf_*"):
    try:
        p.unlink()
    except Exception:
        pass

for ki, key in enumerate(keys, 1):
    print("\n=== KEY", ki, "===")
    placeholders = ["Database.carp", f"bf_out{ki}.kdbx", key]
    for idx, perm in enumerate(itertools.permutations(placeholders, 3), 1):
        cmd = [str(exe), *perm]
        r = subprocess.run(cmd, capture_output=True, text=True)
        print(idx, "RC", r.returncode, "ARGS", perm)
        if r.stdout.strip():
            print("  stdout:", r.stdout.strip())
        if r.stderr.strip():
            print("  stderr:", r.stderr.strip())

        # check possible outputs
        candidates = [
            Path(f"bf_out{ki}.kdbx.decrypt"),
            Path("Database.carp.decrypt"),
            Path((key[:20] + ".decrypt")),
        ]
        hit = False
        for c in candidates:
            if c.exists():
                print("  OUTPUT", c, c.stat().st_size)
                hit = True
        if hit:
            print("  --> candidate success with permutation", idx)
