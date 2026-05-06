# Referenzen und Learnings (Voyage)

This file captures the practical references and key technical takeaways from the solve process.

## Primary Technical References

- Joomla version manifest path:
  - /administrator/manifests/files/joomla.xml
- CVE-2023-23752 public leak endpoints:
  - /api/index.php/v1/config/application?public=true
  - /api/index.php/v1/users?public=true

## External Writeups Reviewed

- https://medium.com/@digistam/tryhackme-voyage-a4cd09183ae6
- https://0xb0b.gitbook.io/writeups/tryhackme/2025/voyage
- https://infosecwriteups.com/recon-728a9aad68a8

## What Was Confirmed in This Workspace

1. SSH port behavior is critical:
- Port 22 rejected password auth (publickey only)
- Port 2222 accepted leaked root password

2. Internal network pivot is real:
- Source container saw internal subnet 192.168.100.0/24
- Internal service of interest at 192.168.100.12:5000

3. Public HTTP surface did not show pickle trigger:
- Timing checks against public endpoints stayed near baseline
- No deserialization signal on tested public routes

4. Internal app deserialization is real:
- session_data cookie is pickle-serialized
- Crafted payloads executed server-side

5. Root path required container escape logic:
- CAP_SYS_MODULE was available
- Module build and insertion path was viable

## Scripts in This Project

- get_user_flag_via_internal_pickle.py
  - Stable, dedicated user-flag retrieval path

- get_root_flag_via_internal_pickle.py
  - Dedicated root-flag path using live LKM flow and internal listener strategy

## Operational Lessons

- HTTP 200 does not prove code execution.
- Timing-based validation is the fastest truth test for deserialization triggers.
- In multi-stage rooms, separate foothold logic from post-foothold logic.
- When callback routing is unstable, prefer in-band/internal capture methods.

## Verification Outputs

- User flag recovered:
  - THM{ee346612fb944085af0dd2cd677b1902}

- Root flag recovered:
  - THM{ace91ec899f84498a74629b078bdceff}
