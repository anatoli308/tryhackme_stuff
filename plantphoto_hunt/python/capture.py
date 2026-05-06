"""Run this on the attackbox: python3 capture.py
Then trigger the SSRF from any machine."""
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print("\n" + "="*60)
        print(f"GET {self.path}")
        for k,v in self.headers.items():
            print(f"  {k}: {v}")
        print("="*60)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        cl = int(self.headers.get('Content-Length',0))
        body = self.rfile.read(cl) if cl else b''
        print("\n" + "="*60)
        print(f"POST {self.path}")
        for k,v in self.headers.items():
            print(f"  {k}: {v}")
        print(f"Body: {body}")
        print("="*60)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

print("Listening on 0.0.0.0:9999 ...")
HTTPServer(("0.0.0.0", 9999), H).serve_forever()
