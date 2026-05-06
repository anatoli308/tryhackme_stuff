# TryHackMe Voyage - Full Solve Guide (User + Root)

This guide documents the exact workflow that worked in this project to solve both flags reliably.

## Scope

- Target platform: TryHackMe Voyage
- Goal: get user-level flag and root-level flag
- Scripts used:
  - get_user_flag_via_internal_pickle.py
  - get_root_flag_via_internal_pickle.py

## Final Flags

- User flag: THM{ee346612fb944085af0dd2cd677b1902}
- Root flag: THM{ace91ec899f84498a74629b078bdceff}

## High-Level Attack Chain

1. Identify Joomla and vulnerable version (4.2.7).
2. Exploit CVE-2023-23752 info leak endpoint.
3. Reuse leaked credential on SSH port 2222 (not 22).
4. Pivot to internal app at 192.168.100.12:5000.
5. Abuse insecure pickle deserialization in session_data cookie.
6. Get user flag from internal container.
7. Use CAP_SYS_MODULE route with kernel module to reach host context.
8. Capture root flag.

## Step 1 - Confirm Joomla + CVE Leak

Useful endpoints:

- /administrator/manifests/files/joomla.xml
- /api/index.php/v1/config/application?public=true
- /api/index.php/v1/users?public=true

Expected key leak data:

- SSH credential reuse candidate: root / RootPassword@1234

## Step 2 - Use Correct SSH Port

Important finding: login is valid on port 2222, while port 22 is publickey-only.

## Step 3 - Get User Flag (Automated)

Run:

```powershell
cd D:\projects\tryhackme\voyage_hunt
python .\get_user_flag_via_internal_pickle.py
```

What it does:

- SSH to target:2222
- Access internal finance app: http://192.168.100.12:5000/
- Login admin/admin
- Send malicious pickle payload in session_data
- Read reflected command output and print the flag

Expected result:

```text
THM{ee346612fb944085af0dd2cd677b1902}
```

## Step 4 - Get Root Flag (Automated)

Run:

```powershell
cd D:\projects\tryhackme\voyage_hunt
python .\get_root_flag_via_internal_pickle.py --listener-timeout 12 --callback-port 4555
```

Why this works:

- The script reuses the internal pickle executor path.
- It writes rev.c + Makefile into /tmp/exp in the second container.
- Builds rev.ko against 6.8.0-1030-aws headers.
- Handles already-loaded module state by unloading and reloading.
- Uses an internal listener approach to avoid external callback routing issues.
- Extracts and prints root flag when callback data arrives.

Expected result:

```text
[+] ROOT FLAG FOUND: THM{ace91ec899f84498a74629b078bdceff}
```

## Troubleshooting

### Symptom: No callback / timeout

- Use a different callback port:

```powershell
python .\get_root_flag_via_internal_pickle.py --listener-timeout 20 --callback-port 4555
```

- Ensure no local process already uses the selected port.

### Symptom: insmod says File exists

- This means module is already loaded.
- Current root script already handles this by trying rmmod rev before insmod.

### Symptom: Public endpoint pickle attempts fail

- Expected for this room path.
- Trigger is internal service path, not the public Joomla endpoints.

## Notes

- This repository workflow intentionally keeps get_user_flag_via_internal_pickle.py stable.
- Root automation is implemented in a separate script.
