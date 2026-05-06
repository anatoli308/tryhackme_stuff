#!/usr/bin/env python3
"""
Scout Port 80 to find working endpoints and HTTP methods.
Identify the actual service and required endpoints.
"""

import requests
import json
from urllib.parse import urljoin

TARGET = "http://10.82.132.75:80"

def test_endpoint(path, method="GET", payload=None):
    """Test an endpoint with different HTTP methods."""
    url = urljoin(TARGET, path)
    
    try:
        if method == "GET":
            resp = requests.get(url, timeout=5)
        elif method == "POST":
            resp = requests.post(url, json=payload or {}, timeout=5)
        elif method == "OPTIONS":
            resp = requests.options(url, timeout=5)
        else:
            return None
            
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "content_sample": resp.text[:300] if resp.text else ""
        }
    except requests.exceptions.Timeout:
        return {"error": "TIMEOUT"}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"CONNECTION_ERROR: {str(e)[:50]}"}
    except Exception as e:
        return {"error": str(e)[:100]}

# Test endpoints
endpoints_to_try = [
    "/",
    "/index.php",
    "/authenticate",
    "/authenticate.php",
    "/api",
    "/api/authenticate",
    "/api/login",
    "/login",
    "/labs",
    "/labs/lab5",
    "/labs/lab6",
    "/challenge",
    "/secure",
]

print(f"[*] Scanning {TARGET}\n")

for endpoint in endpoints_to_try:
    print(f"\n[*] Testing {endpoint}")
    
    # Try GET
    result_get = test_endpoint(endpoint, "GET")
    status = result_get.get("status", "???")
    print(f"    GET  -> HTTP {status}")
    if status == 405:
        print(f"       Headers: {result_get.get('headers', {}).get('Allow', 'N/A')}")
    if result_get.get("content_sample"):
        print(f"       Content: {result_get['content_sample'][:100]}")
    
    # Try POST
    result_post = test_endpoint(endpoint, "POST", {"test": "data"})
    status = result_post.get("status", "???")
    print(f"    POST -> HTTP {status}")
    if result_post.get("content_sample"):
        print(f"       Content: {result_post['content_sample'][:100]}")

print("\n[*] Scan complete")
