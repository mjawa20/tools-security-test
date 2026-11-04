# Cross-origin server for the CVE-2015-9251 check: serves evil.js as JavaScript with CORS open.
import http.server, os, sys
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'evil'))
class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()
    def guess_type(self, path):
        return 'text/javascript'
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
